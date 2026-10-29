//! Binary wire protocol.
//!
//! Every frame is a 5-byte header followed by an opaque payload:
//!
//! ```text
//! Request:   [u8 opcode][u32 length][payload]
//! Response:  [u8 status][u32 length][payload]
//! ```
//!
//! Lengths are big-endian, matching PHP's `pack('N', …)` / `unpack('N', …)`.
//!
//! Length prefixes replace the previous newline/pipe delimiters. Nothing in a
//! key or value needs escaping or sanitising, keys may contain any byte, and a
//! stored value can never be mistaken for a status token — an entire class of
//! parsing bug is removed rather than defended against.

use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ---- Opcodes ----

pub const OP_PING: u8 = 0x01;
pub const OP_STATS: u8 = 0x02;

pub const OP_GET: u8 = 0x10;
pub const OP_PUT: u8 = 0x11;
pub const OP_DELETE: u8 = 0x12;

pub const OP_BATCH_START: u8 = 0x20;
pub const OP_BATCH_COMMIT: u8 = 0x21;
pub const OP_BATCH_ABORT: u8 = 0x22;

pub const OP_CLEAR: u8 = 0x30;

pub const OP_SMT_ROOT: u8 = 0x40;
pub const OP_SMT_LEAF: u8 = 0x41;
pub const OP_SMT_UPDATE: u8 = 0x42;
pub const OP_SMT_PROOF: u8 = 0x43;
pub const OP_SMT_VERIFY: u8 = 0x44;

// ---- Status codes ----

pub const ST_OK: u8 = 0x00;
pub const ST_NOT_FOUND: u8 = 0x01;
/// Payload carries a UTF-8 diagnostic message.
pub const ST_ERROR: u8 = 0x02;
pub const ST_BAD_COMMAND: u8 = 0x03;
pub const ST_QUEUED: u8 = 0x04;
pub const ST_BATCH_TOO_LARGE: u8 = 0x05;
pub const ST_ALREADY_IN_BATCH: u8 = 0x06;

/// Bytes in a node hash.
pub const HASH_LEN: usize = 32;

/// How long to wait for a frame body once its header has arrived.
///
/// There is deliberately no timeout on waiting for the *next* header: an idle
/// connection between operations is normal. But a client that announces a
/// payload and then stalls would otherwise pin a connection slot and up to
/// `max_input_size` of buffer indefinitely, so the body has a deadline.
pub const BODY_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Reads one request frame.
///
/// Returns `Ok(None)` on a clean disconnect at a frame boundary. The payload is
/// read into `payload`, which is reused across calls.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    payload: &mut Vec<u8>,
    max_payload: usize,
) -> std::io::Result<Option<u8>> {
    let mut header = [0u8; 5];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        // A disconnect between frames is normal; mid-header is not, but both
        // leave us with nothing to act on.
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let opcode = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;

    // Checked before allocating, so a bogus length costs nothing.
    if len > max_payload {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("payload of {len} bytes exceeds max_input_size ({max_payload})"),
        ));
    }

    payload.clear();
    payload.resize(len, 0);
    if len > 0 {
        match tokio::time::timeout(BODY_READ_TIMEOUT, reader.read_exact(payload)).await {
            Ok(result) => {
                result?;
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "client announced {len} bytes but stalled for {}s",
                        BODY_READ_TIMEOUT.as_secs()
                    ),
                ));
            }
        }
    }
    Ok(Some(opcode))
}

/// Writes one response frame and flushes it.
pub async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut header = [0u8; 5];
    header[0] = status;
    header[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());

    // Buffered upstream, so header and payload leave as a single syscall.
    writer.write_all(&header).await?;
    if !payload.is_empty() {
        writer.write_all(payload).await?;
    }
    writer.flush().await
}

/// Splits a `[u32 len][first][rest]` payload.
pub fn split_len_prefixed(payload: &[u8]) -> Option<(&[u8], &[u8])> {
    if payload.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    let rest = &payload[4..];
    if rest.len() < len {
        return None;
    }
    Some((&rest[..len], &rest[len..]))
}

/// A domain record, from which the daemon derives the leaf hash itself.
///
/// Clients send fields rather than a precomputed hash so that leaf hashing has
/// exactly one implementation. A divergence in field order or endianness would
/// otherwise produce proofs that fail on-chain, silently.
#[derive(Debug, PartialEq, Eq)]
pub struct LeafRecord<'a> {
    pub pubkey: [u8; HASH_LEN],
    pub price: u64,
    pub nonce: u64,
    pub target_address: &'a str,
    pub domain: &'a str,
}

/// Parses a record payload:
///
/// ```text
/// [32 pubkey][u64 price][u64 nonce][u32 addr_len][target_address][domain]
/// ```
///
/// Integers are big-endian on the wire (`pack('J', …)` in PHP) and are converted
/// to little-endian only inside the hash, matching the prover. Fixed-width fields
/// lead so the trailing domain needs no length of its own.
pub fn parse_record(payload: &[u8]) -> Option<LeafRecord<'_>> {
    const FIXED: usize = HASH_LEN + 8 + 8 + 4;
    if payload.len() < FIXED {
        return None;
    }

    let mut pubkey = [0u8; HASH_LEN];
    pubkey.copy_from_slice(&payload[..HASH_LEN]);

    let price = u64::from_be_bytes(payload[HASH_LEN..HASH_LEN + 8].try_into().ok()?);
    let nonce = u64::from_be_bytes(payload[HASH_LEN + 8..HASH_LEN + 16].try_into().ok()?);
    let addr_len =
        u32::from_be_bytes(payload[HASH_LEN + 16..FIXED].try_into().ok()?) as usize;

    let rest = &payload[FIXED..];
    if rest.len() < addr_len {
        return None;
    }
    let target_address = std::str::from_utf8(&rest[..addr_len]).ok()?;
    let domain = std::str::from_utf8(&rest[addr_len..]).ok()?;
    if domain.is_empty() {
        return None;
    }

    Some(LeafRecord {
        pubkey,
        price,
        nonce,
        target_address,
        domain,
    })
}

/// Terminal kinds in a serialised proof.
pub const TERMINAL_OCCUPIED: u8 = 0x00;
pub const TERMINAL_VACANT: u8 = 0x01;
pub const TERMINAL_BLOCKED: u8 = 0x02;

/// Encodes a record in the same layout clients send to `SMT_UPDATE`, so the two
/// directions share one definition and `parse_record` is its exact inverse.
pub fn encode_record(record: &kns_core::LeafRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(HASH_LEN + 20 + record.target_address.len() + record.domain.len());
    out.extend_from_slice(&record.pubkey);
    out.extend_from_slice(&record.price.to_be_bytes());
    out.extend_from_slice(&record.nonce.to_be_bytes());
    out.extend_from_slice(&(record.target_address.len() as u32).to_be_bytes());
    out.extend_from_slice(record.target_address.as_bytes());
    out.extend_from_slice(record.domain.as_bytes());
    out
}

/// Serialises a root and its proof for `SMT_PROOF`.
///
/// ```text
/// [root: 32][depth: u8][terminal: u8][siblings: 32 * depth]
/// ```
///
/// A `TERMINAL_BLOCKED` proof is followed by the blocking domain's full record, in
/// the layout above. The whole preimage is carried rather than just its key because
/// the circuit must derive the blocking key from the same bytes that produce the
/// blocking leaf hash — see `kerrigan-name-prover/docs/compact-smt.md` §5.3.
///
/// The payload is variable length now: clients must read `depth` and the terminal
/// tag rather than assuming a fixed 128-sibling proof.
pub fn encode_proof(root: &[u8; HASH_LEN], proof: &kns_core::Proof) -> Vec<u8> {
    let mut out = Vec::with_capacity(HASH_LEN * (2 + proof.siblings.len()));
    out.extend_from_slice(root);
    out.push(proof.depth);
    out.push(match &proof.terminal {
        kns_core::Terminal::Occupied => TERMINAL_OCCUPIED,
        kns_core::Terminal::Vacant => TERMINAL_VACANT,
        kns_core::Terminal::Blocked { .. } => TERMINAL_BLOCKED,
    });
    for sibling in &proof.siblings {
        out.extend_from_slice(sibling);
    }
    if let kns_core::Terminal::Blocked { record } = &proof.terminal {
        out.extend_from_slice(&encode_record(record));
    }
    out
}

/// Interprets a payload as a non-empty UTF-8 domain name.
pub fn parse_domain(payload: &[u8]) -> Option<&str> {
    let domain = std::str::from_utf8(payload).ok()?;
    if domain.is_empty() { None } else { Some(domain) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![opcode];
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    // ---- framing ----

    #[tokio::test]
    async fn reads_a_frame_with_payload() {
        let input = frame(OP_GET, b"mykey");
        let mut r = &input[..];
        let mut payload = Vec::new();
        let op = read_request(&mut r, &mut payload, 1024).await.unwrap();
        assert_eq!(op, Some(OP_GET));
        assert_eq!(payload, b"mykey");
    }

    #[tokio::test]
    async fn reads_a_frame_with_empty_payload() {
        let input = frame(OP_PING, b"");
        let mut r = &input[..];
        let mut payload = Vec::new();
        let op = read_request(&mut r, &mut payload, 1024).await.unwrap();
        assert_eq!(op, Some(OP_PING));
        assert!(payload.is_empty());
    }

    #[tokio::test]
    async fn reads_consecutive_frames() {
        let mut input = frame(OP_PING, b"");
        input.extend(frame(OP_GET, b"k"));
        let mut r = &input[..];
        let mut payload = Vec::new();

        assert_eq!(
            read_request(&mut r, &mut payload, 1024).await.unwrap(),
            Some(OP_PING)
        );
        assert!(payload.is_empty());

        assert_eq!(
            read_request(&mut r, &mut payload, 1024).await.unwrap(),
            Some(OP_GET)
        );
        assert_eq!(payload, b"k");
    }

    #[tokio::test]
    async fn clean_disconnect_returns_none() {
        let mut r: &[u8] = b"";
        let mut payload = Vec::new();
        assert_eq!(read_request(&mut r, &mut payload, 1024).await.unwrap(), None);
    }

    #[tokio::test]
    async fn truncated_payload_is_an_error() {
        // Header promises 10 bytes, only 2 follow.
        let mut input = vec![OP_GET];
        input.extend_from_slice(&10u32.to_be_bytes());
        input.extend_from_slice(b"ab");
        let mut r = &input[..];
        let mut payload = Vec::new();
        assert!(read_request(&mut r, &mut payload, 1024).await.is_err());
    }

    #[tokio::test]
    async fn oversized_payload_is_rejected_before_allocating() {
        // Declares 4 GB; must be refused on the header alone.
        let mut input = vec![OP_PUT];
        input.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut r = &input[..];
        let mut payload = Vec::new();
        let err = read_request(&mut r, &mut payload, 1024).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_body_times_out_instead_of_pinning_the_connection() {
        // Header announces 64 bytes; the client then sends nothing and holds the
        // stream open. Without a deadline this would block forever.
        let (mut client, server) = tokio::io::duplex(1024);
        let mut server = server;
        let write = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut hdr = vec![OP_PUT];
            hdr.extend_from_slice(&64u32.to_be_bytes());
            client.write_all(&hdr).await.unwrap();
            // Hold the connection open, sending no body.
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        });

        let mut payload = Vec::new();
        let err = read_request(&mut server, &mut payload, 1024)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        write.abort();
    }

    #[tokio::test]
    async fn payload_exactly_at_the_limit_is_accepted() {
        let input = frame(OP_PUT, &vec![0u8; 1024]);
        let mut r = &input[..];
        let mut payload = Vec::new();
        assert!(read_request(&mut r, &mut payload, 1024).await.is_ok());
        assert_eq!(payload.len(), 1024);
    }

    #[tokio::test]
    async fn binary_payloads_survive_intact() {
        // Bytes that the old text protocol could not carry: newline and pipe.
        let nasty = b"\n|\x00\xff\r\n|value";
        let input = frame(OP_PUT, nasty);
        let mut r = &input[..];
        let mut payload = Vec::new();
        read_request(&mut r, &mut payload, 1024).await.unwrap();
        assert_eq!(payload, nasty);
    }

    #[tokio::test]
    async fn response_roundtrips() {
        let mut out = Vec::new();
        write_response(&mut out, ST_OK, b"value").await.unwrap();
        assert_eq!(out[0], ST_OK);
        assert_eq!(u32::from_be_bytes([out[1], out[2], out[3], out[4]]), 5);
        assert_eq!(&out[5..], b"value");
    }

    #[tokio::test]
    async fn empty_response_is_header_only() {
        let mut out = Vec::new();
        write_response(&mut out, ST_NOT_FOUND, b"").await.unwrap();
        assert_eq!(out.len(), 5);
        assert_eq!(out[0], ST_NOT_FOUND);
    }

    // ---- payload parsers ----

    #[test]
    fn splits_length_prefixed_payload() {
        let mut p = 3u32.to_be_bytes().to_vec();
        p.extend_from_slice(b"keyvalue");
        let (key, value) = split_len_prefixed(&p).unwrap();
        assert_eq!(key, b"key");
        assert_eq!(value, b"value");
    }

    #[test]
    fn splits_with_empty_key_and_empty_value() {
        let mut p = 0u32.to_be_bytes().to_vec();
        p.extend_from_slice(b"v");
        assert_eq!(split_len_prefixed(&p).unwrap(), (&b""[..], &b"v"[..]));

        let p = 0u32.to_be_bytes().to_vec();
        assert_eq!(split_len_prefixed(&p).unwrap(), (&b""[..], &b""[..]));
    }

    #[test]
    fn rejects_malformed_length_prefix() {
        assert!(split_len_prefixed(b"ab").is_none()); // shorter than the prefix
        let mut p = 99u32.to_be_bytes().to_vec(); // claims more than is present
        p.extend_from_slice(b"short");
        assert!(split_len_prefixed(&p).is_none());
    }

    fn record_payload(
        pubkey: [u8; HASH_LEN],
        price: u64,
        nonce: u64,
        addr: &str,
        domain: &str,
    ) -> Vec<u8> {
        let mut p = pubkey.to_vec();
        p.extend_from_slice(&price.to_be_bytes());
        p.extend_from_slice(&nonce.to_be_bytes());
        p.extend_from_slice(&(addr.len() as u32).to_be_bytes());
        p.extend_from_slice(addr.as_bytes());
        p.extend_from_slice(domain.as_bytes());
        p
    }

    #[test]
    fn parses_a_record() {
        let p = record_payload([7u8; HASH_LEN], 1000, 42, "zaddr1", "alice.zec");
        let r = parse_record(&p).unwrap();
        assert_eq!(r.pubkey, [7u8; HASH_LEN]);
        assert_eq!(r.price, 1000);
        assert_eq!(r.nonce, 42);
        assert_eq!(r.target_address, "zaddr1");
        assert_eq!(r.domain, "alice.zec");
    }

    #[test]
    fn parses_a_record_with_an_empty_address() {
        let p = record_payload([0u8; HASH_LEN], 0, 0, "", "a.zec");
        let r = parse_record(&p).unwrap();
        assert_eq!(r.target_address, "");
        assert_eq!(r.domain, "a.zec");
    }

    #[test]
    fn record_survives_large_u64_fields() {
        let p = record_payload([1u8; HASH_LEN], u64::MAX, u64::MAX, "a", "b.zec");
        let r = parse_record(&p).unwrap();
        assert_eq!(r.price, u64::MAX);
        assert_eq!(r.nonce, u64::MAX);
    }

    #[test]
    fn rejects_malformed_records() {
        assert!(parse_record(&[0u8; 10]).is_none()); // shorter than the fixed header
        // Empty domain.
        assert!(parse_record(&record_payload([0u8; HASH_LEN], 1, 1, "a", "")).is_none());
        // Address length runs past the end of the payload.
        let mut p = vec![0u8; HASH_LEN + 16];
        p.extend_from_slice(&99u32.to_be_bytes());
        p.extend_from_slice(b"short");
        assert!(parse_record(&p).is_none());
        // Invalid UTF-8 in the domain.
        let mut p = record_payload([0u8; HASH_LEN], 1, 1, "a", "x");
        p.pop();
        p.push(0xff);
        assert!(parse_record(&p).is_none());
    }

    #[test]
    fn parses_domain_payloads() {
        assert_eq!(parse_domain(b"alice.zec"), Some("alice.zec"));
        assert_eq!(parse_domain(b""), None);
        assert_eq!(parse_domain(&[0xff, 0xfe]), None);
    }
}

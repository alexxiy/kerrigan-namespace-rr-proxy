//! RocksDB-backed node store with an uncommitted-batch overlay.
//!
//! The overlay is what gives read-your-own-writes: tree nodes queued by an open
//! batch are visible to subsequent reads on the same connection before the batch
//! is committed. It doubles as the batch itself — the `WriteBatch` is built from
//! it once, at commit time — so queued entries are held in memory only once.

use crate::smt::{record_key, Hash, Node, NodeKey, NodeStore, EMPTY};
use rocksdb::{DB, SnapshotWithThreadMode, WriteBatch, WriteOptions};
use std::collections::HashMap;
use std::fmt;

/// Uncommitted writes for one connection. `None` is a delete tombstone.
pub type PendingBatch = HashMap<Vec<u8>, Option<Vec<u8>>>;

/// Applies an overlay to the database as one atomic write.
///
/// `sync` forces the WAL to disk. Without it an acknowledged commit survives a
/// process crash but not a power loss, which would break the indexer's MySQL XA
/// recovery invariant.
pub fn commit_overlay(db: &DB, overlay: PendingBatch, sync: bool) -> Result<(), rocksdb::Error> {
    let mut wb = WriteBatch::default();
    for (key, value) in overlay {
        match value {
            Some(v) => wb.put(&key, &v),
            None => wb.delete(&key),
        }
    }
    let mut wo = WriteOptions::default();
    wo.set_sync(sync);
    db.write_opt(wb, &wo)
}

#[derive(Debug)]
pub enum StoreError {
    Db(rocksdb::Error),
    /// A stored node could not be decoded, which means on-disk corruption or a
    /// foreign writer — never a client mistake.
    CorruptNode { value_len: usize },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Db(e) => write!(f, "rocksdb: {e}"),
            StoreError::CorruptNode { value_len } => {
                write!(f, "corrupt node: undecodable value of {value_len} bytes")
            }
        }
    }
}

impl From<rocksdb::Error> for StoreError {
    fn from(e: rocksdb::Error) -> Self {
        StoreError::Db(e)
    }
}

/// Node store over RocksDB, optionally reading through a snapshot and/or an
/// uncommitted batch overlay.
pub struct RocksStore<'a> {
    db: &'a DB,
    /// When set, all committed reads come from this fixed point in time, so a
    /// multi-node read (a proof of ~log2(N) nodes) cannot tear across a concurrent
    /// commit. Short-lived by construction: it never outlives one operation.
    snapshot: Option<SnapshotWithThreadMode<'a, DB>>,
    overlay: PendingBatch,
    in_batch: bool,
}

impl<'a> RocksStore<'a> {
    /// Store for read/write work. Reads see the latest committed data.
    pub fn new(db: &'a DB, overlay: PendingBatch, in_batch: bool) -> Self {
        Self {
            db,
            snapshot: None,
            overlay,
            in_batch,
        }
    }

    /// Store whose committed reads are pinned to a consistent snapshot.
    pub fn snapshotted(db: &'a DB, overlay: PendingBatch, in_batch: bool) -> Self {
        Self {
            db,
            snapshot: Some(db.snapshot()),
            overlay,
            in_batch,
        }
    }

    /// Returns the overlay so the caller can move it back into connection state.
    pub fn into_overlay(self) -> PendingBatch {
        self.overlay
    }

    /// Raw committed-or-overlay read, without the 32-byte node constraint.
    pub fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        if self.in_batch && let Some(entry) = self.overlay.get(key) {
            return Ok(entry.clone());
        }
        let found = match &self.snapshot {
            Some(snap) => snap.get(key)?,
            None => self.db.get(key)?,
        };
        Ok(found)
    }

    /// Raw write: queued into the overlay during a batch, otherwise immediate.
    pub fn put_raw(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StoreError> {
        if self.in_batch {
            self.overlay.insert(key, Some(value));
        } else {
            self.db.put(&key, &value)?;
        }
        Ok(())
    }

    /// Raw delete: queued as a tombstone during a batch, otherwise immediate.
    pub fn delete_raw(&mut self, key: Vec<u8>) -> Result<(), StoreError> {
        if self.in_batch {
            self.overlay.insert(key, None);
        } else {
            self.db.delete(&key)?;
        }
        Ok(())
    }

}

/// On-disk node encoding.
///
/// The kind must be stored, not inferred: in a compact tree a leaf and an internal
/// node can sit at any depth, and the descent has to tell them apart. A leaf also
/// carries its domain, which is what lets a proof name the blocking record.
///
/// ```text
/// internal: [0x00][hash: 32]
/// leaf:     [0x01][hash: 32][domain: utf8]
/// ```
const TAG_INTERNAL: u8 = 0x00;
const TAG_LEAF: u8 = 0x01;

fn encode_node(node: &Node) -> Vec<u8> {
    match node {
        Node::Internal(hash) => {
            let mut v = Vec::with_capacity(1 + 32);
            v.push(TAG_INTERNAL);
            v.extend_from_slice(hash);
            v
        }
        Node::Leaf { hash, domain } => {
            let mut v = Vec::with_capacity(1 + 32 + domain.len());
            v.push(TAG_LEAF);
            v.extend_from_slice(hash);
            v.extend_from_slice(domain.as_bytes());
            v
        }
    }
}

fn decode_node(bytes: &[u8]) -> Result<Node, StoreError> {
    let corrupt = || StoreError::CorruptNode {
        value_len: bytes.len(),
    };
    if bytes.len() < 33 {
        return Err(corrupt());
    }
    let hash: Hash = bytes[1..33].try_into().map_err(|_| corrupt())?;
    match bytes[0] {
        TAG_INTERNAL if bytes.len() == 33 => Ok(Node::Internal(hash)),
        TAG_LEAF => {
            let domain = std::str::from_utf8(&bytes[33..]).map_err(|_| corrupt())?;
            if domain.is_empty() {
                return Err(corrupt());
            }
            Ok(Node::Leaf {
                hash,
                domain: domain.to_string(),
            })
        }
        _ => Err(corrupt()),
    }
}

impl NodeStore for RocksStore<'_> {
    type Error = StoreError;

    fn get_node(&self, key: &NodeKey) -> Result<Option<Node>, Self::Error> {
        match self.get_raw(key.as_slice())? {
            Some(bytes) => Ok(Some(decode_node(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Resolves every key in one pass: entries already queued by the open batch are
    /// served from memory, and whatever remains is fetched with a single `multi_get`
    /// instead of one point lookup per node. A missing node is an empty subtree.
    fn get_hashes(&self, keys: &[NodeKey]) -> Result<Vec<Hash>, Self::Error> {
        let mut out: Vec<Hash> = vec![EMPTY; keys.len()];
        let mut misses: Vec<usize> = Vec::new();

        for (i, key) in keys.iter().enumerate() {
            if self.in_batch
                && let Some(entry) = self.overlay.get(key.as_slice())
            {
                // A tombstone reads as an empty subtree.
                if let Some(v) = entry {
                    out[i] = decode_node(v)?.hash();
                }
            } else {
                misses.push(i);
            }
        }

        if misses.is_empty() {
            return Ok(out);
        }

        let wanted = misses.iter().map(|&i| keys[i].as_slice());
        let fetched = match &self.snapshot {
            Some(snap) => snap.multi_get(wanted),
            None => self.db.multi_get(wanted),
        };

        for (&i, result) in misses.iter().zip(fetched) {
            if let Some(bytes) = result? {
                out[i] = decode_node(&bytes)?.hash();
            }
        }

        Ok(out)
    }

    fn put_node(&mut self, key: &NodeKey, node: &Node) -> Result<(), Self::Error> {
        self.put_raw(key.as_slice().to_vec(), encode_node(node))
    }

    fn delete_node(&mut self, key: &NodeKey) -> Result<(), Self::Error> {
        self.delete_raw(key.as_slice().to_vec())
    }

    fn get_record(&self, domain: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        self.get_raw(&record_key(domain))
    }

    fn put_record(&mut self, domain: &str, payload: &[u8]) -> Result<(), Self::Error> {
        self.put_raw(record_key(domain), payload.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::{NodeKey, Smt};

    /// A record payload in the client wire format, plus the leaf hash it implies.
    fn record(domain: &str) -> (Vec<u8>, Hash) {
        let rec = kns_core::LeafRecord {
            domain: domain.to_string(),
            pubkey: [7u8; 32],
            target_address: "ps1abc".to_string(),
            price: 0,
            nonce: 1,
        };
        (crate::protocol::encode_record(&rec), rec.leaf())
    }

    /// Registers `domain` through the tree, returning the new root.
    fn put(smt: &Smt, store: &mut RocksStore<'_>, domain: &str) -> Hash {
        let (payload, leaf) = record(domain);
        smt.update(store, domain, &payload, leaf).unwrap()
    }

    /// Opens a throwaway database in the scratch directory.
    struct TempDb {
        db: Option<DB>,
        path: std::path::PathBuf,
    }

    impl TempDb {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "rr-proxy-store-test-{}-{}-{:?}",
                tag,
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = DB::destroy(&rocksdb::Options::default(), &path);
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            let db = DB::open(&opts, &path).expect("open temp db");
            Self {
                db: Some(db),
                path,
            }
        }
        fn db(&self) -> &DB {
            self.db.as_ref().unwrap()
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            self.db.take();
            let _ = DB::destroy(&rocksdb::Options::default(), &self.path);
        }
    }

    #[test]
    fn direct_writes_reach_the_database() {
        let t = TempDb::new("direct");
        let mut store = RocksStore::new(t.db(), PendingBatch::new(), false);
        store.put_raw(b"k".to_vec(), b"v".to_vec()).unwrap();
        assert_eq!(store.get_raw(b"k").unwrap(), Some(b"v".to_vec()));
        // Visible outside the store, because no batch was open.
        assert_eq!(t.db().get(b"k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn batched_writes_stay_out_of_the_database() {
        let t = TempDb::new("batched");
        let mut store = RocksStore::new(t.db(), PendingBatch::new(), true);
        store.put_raw(b"k".to_vec(), b"v".to_vec()).unwrap();
        // Read-your-own-writes through the overlay...
        assert_eq!(store.get_raw(b"k").unwrap(), Some(b"v".to_vec()));
        // ...but nothing has been committed.
        assert_eq!(t.db().get(b"k").unwrap(), None);
    }

    #[test]
    fn batched_delete_is_a_tombstone() {
        let t = TempDb::new("tombstone");
        t.db().put(b"k", b"v").unwrap();
        let mut store = RocksStore::new(t.db(), PendingBatch::new(), true);
        store.delete_raw(b"k".to_vec()).unwrap();
        assert_eq!(store.get_raw(b"k").unwrap(), None);
        // Still on disk until the batch commits.
        assert_eq!(t.db().get(b"k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn overlay_survives_the_store() {
        let t = TempDb::new("overlay");
        let mut store = RocksStore::new(t.db(), PendingBatch::new(), true);
        store.put_raw(b"a".to_vec(), b"1".to_vec()).unwrap();
        let overlay = store.into_overlay();
        assert_eq!(overlay.get(b"a".as_slice()), Some(&Some(b"1".to_vec())));
    }

    #[test]
    fn non_hash_sized_node_is_reported_as_corruption() {
        let t = TempDb::new("corrupt");
        let store = RocksStore::new(t.db(), PendingBatch::new(), false);
        // The key must be a real node key, since get_node takes one.
        let key = NodeKey::root();
        t.db().put(key.as_slice(), b"short").unwrap();
        match store.get_node(&key) {
            Err(StoreError::CorruptNode { value_len }) => assert_eq!(value_len, 5),
            other => panic!("expected CorruptNode, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_hides_writes_made_after_it_was_taken() {
        let t = TempDb::new("snapshot");
        t.db().put(b"k", [1u8; 32]).unwrap();

        let store = RocksStore::snapshotted(t.db(), PendingBatch::new(), false);
        // A concurrent committer changes the value...
        t.db().put(b"k", [2u8; 32]).unwrap();
        // ...but the pinned read still sees the original.
        assert_eq!(store.get_raw(b"k").unwrap(), Some([1u8; 32].to_vec()));
    }

    #[test]
    fn smt_update_through_a_batch_is_invisible_until_committed() {
        let t = TempDb::new("smt-batch");
        let smt = Smt::new();

        let mut store = RocksStore::new(t.db(), PendingBatch::new(), true);
        let root = put(&smt, &mut store, "alice.zec");
        // The tree reads its own uncommitted nodes back.
        assert_eq!(smt.root(&store).unwrap(), root);

        let overlay = store.into_overlay();
        assert!(!overlay.is_empty());

        // Nothing was written, so a fresh store still sees an empty tree.
        let clean = RocksStore::new(t.db(), PendingBatch::new(), false);
        assert_eq!(smt.root(&clean).unwrap(), crate::smt::EMPTY);
    }

    #[test]
    fn commit_overlay_applies_puts_and_deletes_atomically() {
        let t = TempDb::new("commit-overlay");
        t.db().put(b"gone", b"v").unwrap();

        let mut overlay = PendingBatch::new();
        overlay.insert(b"new".to_vec(), Some(b"1".to_vec()));
        overlay.insert(b"gone".to_vec(), None);

        commit_overlay(t.db(), overlay, true).unwrap();

        assert_eq!(t.db().get(b"new").unwrap(), Some(b"1".to_vec()));
        assert_eq!(t.db().get(b"gone").unwrap(), None);
    }

    #[test]
    fn an_unbatched_update_is_one_atomic_write() {
        // Regression: writing each spine node individually would leave the tree
        // corrupt if anything failed part-way up. The handler routes an
        // unbatched update through an overlay, so nothing reaches disk until the
        // whole spine is computed.
        let t = TempDb::new("atomic-update");
        let smt = Smt::new();

        let mut store = RocksStore::new(t.db(), PendingBatch::new(), true);
        let root = put(&smt, &mut store, "alice.zec");
        let overlay = store.into_overlay();

        // Still nothing on disk mid-walk.
        assert_eq!(smt.root(&RocksStore::new(t.db(), PendingBatch::new(), false)).unwrap(),
                   crate::smt::EMPTY);
        // A lone leaf sits at the root, so one node plus its record.
        assert_eq!(overlay.len(), 2, "expected one node and one record, got {overlay:?}");

        commit_overlay(t.db(), overlay, true).unwrap();
        let after = RocksStore::new(t.db(), PendingBatch::new(), false);
        assert_eq!(smt.root(&after).unwrap(), root);
    }

    #[test]
    fn smt_update_without_a_batch_persists() {
        let t = TempDb::new("smt-direct");
        let smt = Smt::new();

        let mut store = RocksStore::new(t.db(), PendingBatch::new(), false);
        let root = put(&smt, &mut store, "alice.zec");

        let reopened = RocksStore::new(t.db(), PendingBatch::new(), false);
        assert_eq!(smt.root(&reopened).unwrap(), root);
        // The leaf is derived from the record, so compare against that rather than
        // an arbitrary literal.
        assert_eq!(smt.leaf(&reopened, "alice.zec").unwrap(), Some(record("alice.zec").1));
    }

    #[test]
    fn proof_from_a_batched_tree_reflects_queued_updates() {
        let t = TempDb::new("smt-proof-batch");
        let smt = Smt::new();

        let mut store = RocksStore::new(t.db(), PendingBatch::new(), true);
        put(&smt, &mut store, "alice.zec");
        let root = put(&smt, &mut store, "bob.zec");

        // A proof taken mid-batch must be consistent with the mid-batch root, which
        // is what batchProcessor relies on when it proves each command in sequence
        // before committing. Checked with the circuit's own verifier, not a
        // transcription of it.
        let proof = smt.proof(&store, "alice.zec").unwrap();
        let (_, leaf) = record("alice.zec");
        let (reconstructed, _) =
            kns_core::verify_and_apply("alice.zec", &proof, Some(leaf), [0xAAu8; 32]);
        assert_eq!(reconstructed, root);
    }
}

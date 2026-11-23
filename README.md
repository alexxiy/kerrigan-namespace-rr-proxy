# KNS RocksDB & Sparse Merkle Tree Daemon (`rr-proxy`)

A lightweight, high-performance Unix socket daemon written in Rust. It owns the **Sparse Merkle Tree (SMT)** behind Kerrigan NameSpace (KNS) and exposes it to clients that lack native thread-safe or high-performance RocksDB bindings (such as PHP), over a binary protocol on a Unix domain socket.

## SMT Handling in Kerrigan NameSpace

Sparse Merkle Trees generate cryptographic proofs and rewrite tree structure across many operations per block, so they need low-latency reads and writes. During a single update sequence, parent nodes must be read immediately after being written but before the batch is committed.

**Tree traversal lives in the daemon**, not in the client. A domain update or a proof is a single round trip rather than the many a client-side tree walk required, the tree walk runs in native code, and a proof is always served with the root it was built from — from one database snapshot, so the two can never describe different states.

Leaf hashing also lives here. Clients send record *fields*, never a precomputed hash, so the leaf format has exactly one implementation — shared with the on-chain prover. The test suite pins the tree's traversal, bit order and leaf format against a transcription of the prover's own verifier, so a divergence fails a test instead of silently producing proofs that fail on-chain.

## Features

- **Asynchronous & Concurrent**: Built on Tokio, spawning dedicated task handlers for concurrent client connections. Blocking database work runs on the blocking pool.
- **Native Sparse Merkle Tree**: Update, proof, leaf lookup and state verification are single commands.
- **Atomic Spine Writes**: An update rewrites only the nodes on the domain's path — the leaf plus the ~log2(N) nodes above it (the spine); they always land as one atomic batch, whether or not a transaction is open.
- **Transactional Write Batches**: Atomic writes via RocksDB `WriteBatch`, with `fsync` on commit so an acknowledged commit survives power loss.
- **Read-Your-Own-Writes (RYOW)**: A transaction-scoped overlay makes queued nodes visible to later reads on the same connection before commitment.
- **Snapshot-Consistent Proofs**: `SMT_PROOF` returns the root and the path's siblings (~log2(N), variable) from a single snapshot.
- **Proof Lists**: `SMT_PROOFS` returns the proofs of up to 1000 domains against one root, from a single snapshot, in one round trip.
- **Compact Storage**: Node keys are packed path bits (17 bytes at the leaf, versus 128 ASCII characters) and values are raw 32-byte hashes.
- **Tuned for Performance**: Configurable background jobs, write buffer size, LRU block cache, and bloom filters covering both SST and memtable reads.
- **Graceful Lifecycle Management**: Stops accepting, flushes RocksDB and cleans up the socket on SIGTERM/SIGINT.

> [!IMPORTANT]
> Batches are **atomic** and provide read-your-own-writes **per connection**, but writes are not *isolated* from each other: two connections writing at once would each rehash a spine from a state without the other's writes, and one acknowledged update would be lost. So the daemon admits **one writer at a time**. A connection holds the write lock from `BATCH_START` to `BATCH_COMMIT`/`BATCH_ABORT`, or for one write outside a batch, and loses it when it closes. Meanwhile any other connection's `PUT`, `DELETE`, `SMT_UPDATE`, `BATCH_START` or `CLEAR` is answered `BUSY` and does nothing; reads are never refused. Each tree (indexer, registrar) runs its own instance against its own database, with a **single writer** each, so `BUSY` means a second writer was started by mistake.

## Socket Protocol

A binary, length-prefixed protocol. Every frame is a 5-byte header followed by an opaque payload:

```text
Request:   [u8 opcode][u32 length][payload]
Response:  [u8 status][u32 length][payload]
```

Lengths are **big-endian** (`pack('N', …)` in PHP). Because payloads are length-prefixed rather than delimited, keys and values may contain **any byte** — there is nothing to escape, no reserved characters, and a stored value can never be mistaken for a status code.

Every request produces exactly one response, including unrecognised opcodes (`BAD_COMMAND`), so the request/response lockstep cannot desynchronise. A payload larger than `max_input_size` is rejected from the header alone, before anything is allocated.

### Status codes

| Code | Name | Meaning |
| :--- | :--- | :--- |
| `0x00` | `OK` | Success; payload holds the result, if any |
| `0x01` | `NOT_FOUND` | Key or leaf absent, or a verification mismatch |
| `0x02` | `ERROR` | Payload holds a UTF-8 diagnostic message |
| `0x03` | `BAD_COMMAND` | Unknown opcode or malformed payload |
| `0x04` | `QUEUED` | Accepted into the open batch |
| `0x05` | `BATCH_TOO_LARGE` | Batch entry limit reached; commit and continue |
| `0x06` | `ALREADY_IN_BATCH` | A batch is already open on this connection |
| `0x07` | `BUSY` | A write refused, with nothing done: another connection is writing (see above) |

### Sparse Merkle Tree commands

| Op | Name | Payload | Response payload |
| :--- | :--- | :--- | :--- |
| `0x40` | `SMT_ROOT` | — | 32-byte root |
| `0x41` | `SMT_LEAF` | domain | 32-byte leaf, or `NOT_FOUND` |
| `0x42` | `SMT_UPDATE` | record | 32-byte new root |
| `0x43` | `SMT_PROOF` | domain | variable-length compact proof (see below) |
| `0x44` | `SMT_VERIFY` | record | empty; `OK` if the stored leaf matches the record, else `NOT_FOUND` |
| `0x45` | `SMT_PROOFS` | `[u32 len][domain]` × 1..1000 | one root and every domain's proof (see below) |

A **record** is the domain's full state, from which the daemon derives the leaf hash:

```text
[32 pubkey][u64 price][u64 nonce][u32 addr_len][target_address][domain]
```

Integers are big-endian on the wire and converted to little-endian inside the hash, matching the prover. Fixed-width fields lead, so the trailing domain needs no length of its own.

#### `SMT_PROOF` response format

A proof is **variable length**: the compact tree carries only the siblings on the domain's path (~log2(N)), not a fixed 128-level ladder.

```text
[32-byte root][u8 depth][u8 terminal][depth × 32-byte siblings]
```

- `depth` is the number of siblings that follow (`0..=128`); siblings are **deepest first**.
- `terminal` tags the leaf slot the path reached: `0x00` OCCUPIED, `0x01` VACANT, `0x02` BLOCKED.
- A **BLOCKED** (`0x02`) proof is followed by the blocking domain's full **record** (the layout above). The whole preimage is sent, not just a key, because the circuit must derive the blocking key from the same bytes that produce its leaf hash (see `kerrigan-name-prover/docs/compact-smt.md` §5.3).

The leaf's own hash is never sent — the client recomputes it from the record and rehashes up through the siblings to check the root.

#### `SMT_PROOFS` response format

The proofs of a list of domains, all read from one snapshot, so all against the one root sent first. Each is the `SMT_PROOF` payload above without its root, length-prefixed, in the order the request named the domains:

```text
[32-byte root][u32 count]
count × [u32 length][u8 depth][u8 terminal][depth × 32-byte siblings][record, if BLOCKED]
```

A request naming no domain, more than 1000, an empty one, or ending inside an entry is answered `BAD_COMMAND`. An rr-proxy older than this command answers `BAD_COMMAND` (`unknown opcode`) too; the indexer then asks `SMT_PROOF` for each domain, as before.

### Key/value and administrative commands

Raw key/value access is retained for maintenance and diagnostics; normal operation uses the SMT commands above.

`PUT` and `DELETE` are refused (`BAD_COMMAND`) for a key in one of the tree's key spaces: a first byte of `0x00`–`0x80` (a node, by its depth) or `0xFF` (a record). Only `SMT_UPDATE` writes there, since one node changed without the spine above it leaves a root that no longer hashes the tree, and proofs that fail. `GET` reads any key.

| Op | Name | Payload | Response payload |
| :--- | :--- | :--- | :--- |
| `0x01` | `PING` | — | empty |
| `0x02` | `STATS` | — | UTF-8 `keys=… memtables=… …` |
| `0x10` | `GET` | key | value, or `NOT_FOUND` |
| `0x11` | `PUT` | `[u32 keylen][key][value]` | empty |
| `0x12` | `DELETE` | key | empty |
| `0x20` | `BATCH_START` | — | empty |
| `0x21` | `BATCH_COMMIT` | — | empty |
| `0x22` | `BATCH_ABORT` | — | empty |
| `0x30` | `CLEAR` | — | empty |

`CLEAR` wipes every key with a range delete and then compacts, so on a large database it can take a while — size the client read timeout accordingly. It is refused while a batch is open on the connection.

An `SMT_UPDATE` that fails inside a batch (or a command whose task panics there) loses the writes the batch had queued. The batch then stays open but failed: every command except `PING`, `STATS` and `BATCH_ABORT` is answered `ERROR` (`the batch failed: abort it`), until the client sends `BATCH_ABORT` or closes the connection. Nothing of it is written. Outside a batch a failed update leaves nothing behind. The PHP clients end the run on any error, and with it the connection.

## Configuration

The proxy is configured via a TOML file. Below is an example configuration file:

```toml
[server]
socket_path = "/run/rr-proxy/rr-proxy.sock"
socket_perms = "0660"

[logging]
# Optional. When unset, logs go to stdout (captured by journald under systemd).
log_file = "/opt/rr-proxy/logs/rr-proxy.log"
level = "info"

[database]
db_path = "/opt/rr-proxy/db/indexer_rocksdb"
create_if_missing = false

[tuning]
max_background_jobs = 4
write_buffer_size_mb = 64
max_open_files = 10000
max_input_size = 16777216
block_cache_size_mb = 128
sync_on_commit = true
max_batch_entries = 1000000
```

| Key | Default | Notes |
| :--- | :--- | :--- |
| `server.socket_perms` | — | Octal, e.g. `"0660"`. A malformed value is a fatal error, never a silent fallback to the umask. |
| `logging.log_file` | stdout | Opened with `O_APPEND`, so logrotate `copytruncate` is safe. |
| `logging.level` | `info` | `trace` \| `debug` \| `info` \| `warn` \| `error`. |
| `database.create_if_missing` | `false` | Kept off so a mistyped path or unmounted volume fails loudly instead of serving an empty tree. Set `true` once, for first-run initialisation. |
| `tuning.sync_on_commit` | `true` | `fsync` the WAL on `BATCH_COMMIT`. Required for the indexer's MySQL XA two-phase commit to stay consistent across a power loss. Costs one `fsync` per checkpoint. |
| `tuning.max_batch_entries` | `1000000` | Caps daemon memory held by an open batch. Past this the client receives `BATCH_TOO_LARGE` and should commit and continue. |
| `tuning.max_connections` | `64` | Concurrent connections (1–65536). One past it is closed at once. |
| `tuning.shutdown_drain_secs` | `15` | How long a stop waits for open connections to finish the request they are on. |
| `tuning.idle_timeout_secs` | `600` | Closes a connection that sends nothing for this long, unless it has a batch open (its client may be waiting on slow work). `0` never closes one. The PHP client connects again when it finds its idle connection closed. |

## Running the Proxy

Build the daemon:
```bash
cargo build --release
```

`rust-toolchain.toml` pins the compiler (Rust 1.100.0, the newest stable release); rustup installs it on first use.

The protocol's hash rules come from `kns-core`, fetched from the prover repository at the commit `Cargo.toml` pins (the prover's tag v0.1.0), so no prover checkout is needed. To build against a local one instead, while changing `kns-core`:
```bash
cargo build --release --config 'patch."https://github.com/alexxiy/kerrigan-namespace-prover".kns-core.path="../kerrigan-name-prover/kns-core"'
```
That drops kns-core's source from `Cargo.lock`; restore it (`git checkout Cargo.lock`) before committing.

Run manually (note that the `--config` parameter is required):
```bash
./target/release/rr-proxy --config config.toml
```

## Systemd Service Deployment

A systemd service unit template is provided in [contrib/rr-proxy.service](contrib/rr-proxy.service) to run the proxy as a daemon. 

A deployment runs two daemons, the indexer's and the registrar's, each with its own config (see [config.toml](config.toml)). [contrib/rr-proxy@.service](contrib/rr-proxy@.service) runs any number of them: the instance `rr-proxy@kerrigan-indexer` reads `/opt/rr-proxy/kerrigan-indexer.toml`. See [Several Instances](#several-instances).

### Installation Steps

1. Copy the executable to `/opt/rr-proxy/`:
   ```bash
   sudo mkdir -p /opt/rr-proxy
   sudo cp target/release/rr-proxy /opt/rr-proxy/
   ```

2. Copy the configuration file to `/opt/rr-proxy/config.toml` and configure your paths. Ensure the `socket_path` is set to `/run/rr-proxy/rr-proxy.sock`:
   ```bash
   sudo cp config.toml /opt/rr-proxy/config.toml
   ```

3. Create the database and log directories, owned by the service user:
   ```bash
   sudo mkdir -p /opt/rr-proxy/db /opt/rr-proxy/logs
   ```

4. Copy the service file to `/etc/systemd/system/`:
   ```bash
   sudo cp contrib/rr-proxy.service /etc/systemd/system/
   ```

5. Edit the `/etc/systemd/system/rr-proxy.service` file to replace `{{USER}}` and `{{GROUP}}` with the appropriate user and group names.

6. Install the log rotation policy. It rotates every `*.log` in `/opt/rr-proxy/logs`, whatever file `logging.log_file` names:
   ```bash
   sudo cp contrib/rr-proxy.logrotate /etc/logrotate.d/rr-proxy
   ```

7. Reload systemd, enable, and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable rr-proxy
   sudo systemctl start rr-proxy
   ```

> [!NOTE]
> The service utilizes `RuntimeDirectory=rr-proxy` which configures systemd to automatically create `/run/rr-proxy/` (owned by your configured `User`/`Group` with mode `0750` permissions) before launching the binary. `RuntimeDirectoryPreserve=yes` keeps it when the daemon stops; the daemon unlinks its own socket.

> [!IMPORTANT]
> The socket is created with mode `0660`, so **client processes must belong to the configured `Group`** to connect. The `ReadWritePaths=` entries in the unit file must also match `database.db_path` and `logging.log_file` in `config.toml` — under `ProtectSystem=strict` any path not listed is mounted read-only, and the daemon will fail to open its database.

> [!NOTE]
> Both units sandbox the daemon beyond `ProtectSystem=strict`: no capabilities, no devices, no home directories, Unix sockets only (`RestrictAddressFamilies=AF_UNIX`), no writable-and-executable memory, and system calls limited to `@system-service` without `@privileged`. A call outside that set fails with `EPERM` instead of killing the daemon, so the operation that needed it fails with "Operation not permitted" in the daemon's log (`logging.log_file`, or the journal when it is unset).

### Several Instances

Steps 1, 3 and 6 above are the same. Then, per instance, a config named after it, with its own `socket_path`, `db_path` and `log_file` (the database and log under `/opt/rr-proxy/db` and `/opt/rr-proxy/logs`, which the unit makes writable):

```bash
sudo cp config.toml /opt/rr-proxy/kerrigan-indexer.toml     # kerrigan-indexer.sock, kerrigan_indexer_rocksdb, kerrigan-indexer.log
sudo cp config.toml /opt/rr-proxy/kerrigan-registrar.toml   # kerrigan-registrar.sock, its own db_path and log_file
sudo cp contrib/rr-proxy@.service /etc/systemd/system/  # then replace {{USER}} and {{GROUP}} in it
sudo systemctl daemon-reload
sudo systemctl enable --now rr-proxy@kerrigan-indexer rr-proxy@kerrigan-registrar
```

Every instance shares `/run/rr-proxy/`, each with its own socket in it. Moving from `rr-proxy.service` to instances: stop and disable `rr-proxy`, rename its `config.toml` after the instance, and start that instance; the socket, database and log paths stay what the config says.

## License

This project is licensed under the GNU Affero General Public License v3.0. For details, see the [LICENSE](LICENSE) file.

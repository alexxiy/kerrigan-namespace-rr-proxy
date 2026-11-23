//! # rr-proxy — KNS RocksDB & Sparse Merkle Tree Daemon
//!
//! A Unix-socket daemon owning the Sparse Merkle Tree (SMT) behind the KNS name
//! service, exposed to clients that lack native, thread-safe, high-performance
//! RocksDB bindings (notably PHP).
//!
//! Tree traversal lives here rather than in the client. A domain update or proof
//! costs one round trip instead of the many a client-side implementation needs,
//! the tree walk runs in native code, and a proof is served with its root
//! from a single snapshot — so the two can never disagree.
//!
//! Batches are atomic and provide read-your-own-writes per connection. Writes are
//! not isolated from each other, so only one connection writes at a time: while one
//! has a batch open or a write running, another's writes are refused (`BUSY`); reads
//! never wait. Each tree (indexer, registrar) runs its own instance against its own
//! database, with a single writer each.
//!
//! See `src/protocol.rs` for the wire format and `src/smt.rs` for the tree.

mod protocol;
mod smt;
mod store;

use clap::Parser;
use rocksdb::{BlockBasedOptions, Cache, IteratorMode, Options, WriteBatch, WriteOptions, DB};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Semaphore, broadcast};
use tracing::{debug, error, info, warn};

use protocol::*;
use smt::{DEPTH, Smt};
use store::{PendingBatch, RocksStore};

// =====================================================================
// 1. COMMAND LINE ARGUMENTS & CONFIGURATION
// =====================================================================

#[derive(Parser, Debug)]
#[command(author, version, about = "KNS RocksDB & SMT Daemon", long_about = None)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long)]
    config: String,
}

#[derive(Deserialize, Debug)]
struct Config {
    server: ServerConfig,
    #[serde(default)]
    logging: LoggingConfig,
    database: DatabaseConfig,
    tuning: TuningConfig,
}

#[derive(Deserialize, Debug)]
struct ServerConfig {
    socket_path: String,
    socket_perms: String,
}

#[derive(Deserialize, Debug, Default)]
struct LoggingConfig {
    /// Optional log file. When unset, logs go to stdout (journald under systemd).
    ///
    /// The file is opened with `O_APPEND`, which makes it safe to rotate with
    /// logrotate's `copytruncate` — after truncation, writes resume at offset 0
    /// instead of leaving a sparse hole.
    log_file: Option<String>,
    /// trace | debug | info | warn | error
    level: Option<String>,
}

#[derive(Deserialize, Debug)]
struct DatabaseConfig {
    db_path: String,
    /// Create the database if it does not exist. Defaults to `false` so that a
    /// mistyped path or an unmounted volume fails loudly instead of silently
    /// serving an empty tree.
    create_if_missing: Option<bool>,
}

#[derive(Deserialize, Debug)]
struct TuningConfig {
    max_background_jobs: i32,
    write_buffer_size_mb: usize,
    max_open_files: i32,
    max_input_size: usize,
    block_cache_size_mb: Option<usize>,
    /// fsync the WAL on batch commit. Required for the indexer's MySQL XA
    /// two-phase commit to be crash-consistent across a power loss.
    sync_on_commit: Option<bool>,
    /// Upper bound on entries queued in a single batch, to cap daemon memory.
    max_batch_entries: Option<usize>,
    /// Maximum concurrent client connections.
    max_connections: Option<usize>,
    /// How long to wait for in-flight connections to finish on shutdown.
    shutdown_drain_secs: Option<u64>,
    /// Close a connection that sends nothing for this long, unless it has a batch open
    /// (a batch may wait on its client's slow work). `0` never closes one.
    idle_timeout_secs: Option<u64>,
}

/// Per-connection settings, cheap to copy into each spawned task.
#[derive(Clone, Copy)]
struct Settings {
    max_input_size: usize,
    sync_on_commit: bool,
    max_batch_entries: usize,
    /// `None`: idle connections stay open.
    idle_timeout: Option<Duration>,
}

/// Ceiling on concurrent connections; also the permit count used to drain them.
const DEFAULT_MAX_CONNECTIONS: usize = 64;
const DEFAULT_DRAIN_SECS: u64 = 15;
/// Long enough for any client that pauses between requests; a client that finds its
/// idle connection closed connects again (the PHP client does so outside a batch).
const DEFAULT_IDLE_SECS: u64 = 600;

/// Helper to load and parse the TOML configuration file
fn load_config(path: &str) -> Config {
    let config_content = fs::read_to_string(path).unwrap_or_else(|_| {
        eprintln!("FATAL: Could not read configuration file at {}", path);
        std::process::exit(1);
    });
    toml::from_str(&config_content).unwrap_or_else(|e| {
        eprintln!("FATAL: Failed to parse config TOML: {}", e);
        std::process::exit(1);
    })
}

/// Rejects configurations that would produce a daemon that cannot serve requests.
///
/// Returns the parsed socket mode, so the caller cannot re-parse it and cannot
/// reach a state where an invalid mode was accepted.
fn validate_config(config: &Config) -> Result<u32, String> {
    if config.tuning.max_input_size == 0 {
        return Err("tuning.max_input_size must be greater than 0".into());
    }
    if config.tuning.write_buffer_size_mb == 0 {
        return Err("tuning.write_buffer_size_mb must be greater than 0".into());
    }
    if config.tuning.max_background_jobs < 1 {
        return Err("tuning.max_background_jobs must be at least 1".into());
    }
    if config.server.socket_path.is_empty() {
        return Err("server.socket_path must not be empty".into());
    }
    // Parsed here rather than at bind time so a malformed mode is fatal instead of
    // silently leaving the socket at whatever the umask produced.
    let socket_mode = u32::from_str_radix(&config.server.socket_perms, 8).map_err(|_| {
        format!(
            "server.socket_perms '{}' is not octal",
            config.server.socket_perms
        )
    })?;
    if config.tuning.max_batch_entries == Some(0) {
        return Err("tuning.max_batch_entries must be greater than 0".into());
    }
    // Upper bound as well as lower: the permit count is cast to u32 when draining,
    // and a value this large is a typo rather than an intent.
    if let Some(n) = config.tuning.max_connections
        && (n == 0 || n > 65_536)
    {
        return Err("tuning.max_connections must be between 1 and 65536".into());
    }
    Ok(socket_mode)
}

/// Initialises tracing to either a file or stdout.
fn init_logging(cfg: &LoggingConfig) -> Result<(), String> {
    let level = cfg.level.as_deref().unwrap_or("info");
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .map_err(|e| format!("invalid logging.level '{}': {}", level, e))?;

    match &cfg.log_file {
        Some(path) => {
            let file = fs::OpenOptions::new()
                .create(true)
                .append(true) // O_APPEND — see LoggingConfig::log_file
                .open(path)
                .map_err(|e| format!("cannot open log file {}: {}", path, e))?;
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(Mutex::new(file))
                .init();
        }
        None => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }
    Ok(())
}

// =====================================================================
// 2. DATABASE HELPERS (blocking — must not run on the async executor)
// =====================================================================

fn open_db(config: &Config) -> Result<DB, rocksdb::Error> {
    let mut opts = Options::default();
    opts.create_if_missing(config.database.create_if_missing.unwrap_or(false));
    opts.set_max_background_jobs(config.tuning.max_background_jobs);
    opts.set_write_buffer_size(config.tuning.write_buffer_size_mb * 1024 * 1024);
    opts.set_max_open_files(config.tuning.max_open_files);

    // The workload is 100% point lookups on small values, so extend the bloom filter
    // to cover memtable reads as well as SST reads.
    //
    // Both calls are required: whole-key filtering is documented as taking effect only
    // when memtable_prefix_bloom_size_ratio is non-zero, and it defaults to zero — so
    // setting whole-key filtering alone is silently a no-op.
    opts.set_memtable_prefix_bloom_ratio(0.1);
    opts.set_memtable_whole_key_filtering(true);

    // Optimize lookups with a Bloom Filter and LRU Block Cache
    let cache_size = config.tuning.block_cache_size_mb.unwrap_or(128) * 1024 * 1024;
    let cache = Cache::new_lru_cache(cache_size);

    let mut block_opts = BlockBasedOptions::default();
    block_opts.set_block_cache(&cache);
    block_opts.set_bloom_filter(10.0, false); // 10 bits per key, full filter (false for block_based)

    // Account index and filter blocks against the configured cache budget. Without
    // this they are loaded outside the cache and grow with max_open_files, so real
    // memory use silently exceeds block_cache_size_mb.
    block_opts.set_cache_index_and_filter_blocks(true);
    block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);

    opts.set_block_based_table_factory(&block_opts);

    DB::open(&opts, &config.database.db_path)
}

/// Wipes every key using a range delete.
///
/// Deleting key-by-key into one `WriteBatch` would materialise a delete record for
/// every key in the database before writing anything — gigabytes of RAM on a
/// full-size tree, which is precisely when a wipe is requested (full resync).
/// A range delete is O(1) in memory regardless of database size.
fn clear_db(db: &DB) -> Result<(), rocksdb::Error> {
    // Both bounds come from one snapshot: read separately, a write landing
    // between them could leave keys outside the range about to be deleted.
    //
    // The snapshot is scoped to just these two reads and released before the
    // compaction below. A live snapshot pins every version it can still see, so
    // holding it across `compact_range` would stop the compaction dropping the
    // deleted data — the wipe would succeed logically while reclaiming no disk
    // at all, and each resync would grow the database instead of resetting it.
    let (first, last) = {
        let snapshot = db.snapshot();
        let first = snapshot.iterator(IteratorMode::Start).next().transpose()?;
        let last = snapshot.iterator(IteratorMode::End).next().transpose()?;
        (first, last)
    };

    if let (Some((from, _)), Some((to, _))) = (first, last) {
        let mut wb = WriteBatch::default();
        wb.delete_range(&from, &to); // end bound is exclusive...
        wb.delete(&to); // ...so remove the final key explicitly

        let mut wo = WriteOptions::default();
        wo.set_sync(true); // a wipe must survive a crash
        db.write_opt(wb, &wo)?;

        // Range deletes leave tombstones that cost read amplification until compacted.
        db.compact_range(None::<&[u8]>, None::<&[u8]>);
    }
    Ok(())
}

fn collect_stats(db: &DB) -> String {
    let prop = |name: &str| -> String {
        db.property_value(name)
            .ok()
            .flatten()
            .unwrap_or_else(|| "?".to_string())
    };
    format!(
        "keys={} memtables={} table_readers={} pending_compaction={}",
        prop("rocksdb.estimate-num-keys"),
        prop("rocksdb.cur-size-all-mem-tables"),
        prop("rocksdb.estimate-table-readers-mem"),
        prop("rocksdb.estimate-pending-compaction-bytes"),
    )
}

// =====================================================================
// 3. SOCKET LIFECYCLE
// =====================================================================

/// Removes a stale socket left behind by a hard crash.
///
/// The path is only unlinked if it really is a socket, so a misconfigured
/// `socket_path` pointing at a regular file cannot destroy it.
fn remove_stale_socket(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            fs::remove_file(path).map_err(|e| format!("cannot remove stale socket: {}", e))
        }
        Ok(_) => Err(format!(
            "{} exists and is not a socket — refusing to remove it",
            path.display()
        )),
        Err(_) => Ok(()), // nothing there
    }
}

/// Binds the listener with its final permissions already applied.
///
/// The socket is created at a temporary path, chmod'ed, then atomically renamed into
/// place. This removes the window in which the socket is reachable at its published
/// path while still carrying umask-derived permissions.
fn bind_socket(path: &Path, mode: u32) -> Result<UnixListener, String> {
    remove_stale_socket(path)?;

    // Same is-a-socket guard as the published path, so a stray regular file here is
    // reported rather than silently destroyed.
    let tmp_path = path.with_extension("binding");
    remove_stale_socket(&tmp_path)?;

    let listener = UnixListener::bind(&tmp_path)
        .map_err(|e| format!("cannot bind {}: {}", tmp_path.display(), e))?;

    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("cannot set socket permissions: {}", e))?;

    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("cannot publish socket at {}: {}", path.display(), e)
    })?;

    Ok(listener)
}

// =====================================================================
// 4. CLIENT CONNECTION & TRANSACTION LOOP
// =====================================================================

/// Entries written per SMT update: the record, the leaf, and one node per level up to
/// the root.
/// Worst-case writes for one update, used only to decide when a client's batch
/// is too large. The compact tree normally touches ~log2(N) nodes, but a split can
/// push two leaves down to the bit where their keys diverge, so the bound stays at
/// the tree depth rather than the expected depth. At its worst the keys diverge at the
/// last bit: the two leaves at depth `DEPTH`, the internals at every depth above them,
/// and the record - `DEPTH + 3` (`Smt::update`; the slot the other leaf vacates is one
/// of those internals).
const NODES_PER_UPDATE: usize = DEPTH + 3;

/// Whether a raw key lies in one of the tree's key spaces (`smt` module docs): a node,
/// whose first byte is a depth (`0..=DEPTH`), or a record (`RECORD_PREFIX`). Those are
/// written by SMT_UPDATE only. A raw PUT or DELETE there would change one node or record
/// without the spine above it - a tree whose root no longer hashes its contents, and
/// whose proofs then fail.
fn in_tree_keyspace(key: &[u8]) -> bool {
    matches!(key.first(), Some(&b) if usize::from(b) <= DEPTH || b == smt::RECORD_PREFIX)
}

/// The one connection allowed to write the database at a time.
///
/// Writes are not isolated from each other: two connections writing at once each
/// rehash a spine from a state without the other's writes, and the last commit wins -
/// the other's acknowledged update is lost, and its record left behind. The clients
/// keep to one writer per database under their own locks; this makes the daemon refuse
/// a second writer (`BUSY`) instead of relying on that. A connection holds it from
/// `BATCH_START` to `BATCH_COMMIT`/`BATCH_ABORT`, or for the length of one write
/// outside a batch, and loses it when it closes. Reads never take it.
#[derive(Default)]
struct WriterLock {
    owner: Mutex<Option<u64>>,
}

impl WriterLock {
    /// Takes the lock for connection `id`, or keeps it when `id` already holds it.
    /// False while another connection holds it.
    fn acquire(&self, id: u64) -> bool {
        // Nothing panics while holding it, so a poisoned lock still holds a valid owner.
        let mut owner = self.owner.lock().unwrap_or_else(|p| p.into_inner());
        match *owner {
            None => {
                *owner = Some(id);
                true
            }
            Some(holder) => holder == id,
        }
    }

    /// Gives the lock up if connection `id` holds it.
    fn release(&self, id: u64) {
        let mut owner = self.owner.lock().unwrap_or_else(|p| p.into_inner());
        if *owner == Some(id) {
            *owner = None;
        }
    }
}

/// Gives a connection's writer lock up however its task ends: a return, a client
/// that went away, a shutdown.
struct WriterRelease<'a> {
    lock: &'a WriterLock,
    id: u64,
}

impl Drop for WriterRelease<'_> {
    fn drop(&mut self) {
        self.lock.release(self.id);
    }
}

/// Source of connection ids for the writer lock.
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// What every connection to one database shares.
#[derive(Clone)]
struct Shared {
    db: Arc<DB>,
    tree: Arc<Smt>,
    writers: Arc<WriterLock>,
    settings: Settings,
}

/// Resolves once a connection has been idle for `limit`; never, without one.
async fn idle_expiry(limit: Option<Duration>) {
    match limit {
        Some(limit) => tokio::time::sleep(limit).await,
        None => std::future::pending::<()>().await,
    }
}

async fn handle_connection(
    mut socket: UnixStream,
    shared: Shared,
    mut shutdown: broadcast::Receiver<()>,
) {
    let Shared {
        db,
        tree,
        writers,
        settings,
    } = shared;
    let id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    let _release = WriterRelease {
        lock: &writers,
        id,
    };

    let (reader, writer) = socket.split();
    let mut reader = BufReader::new(reader);
    // Buffered so a response header and its payload leave as a single syscall.
    let mut writer = BufWriter::new(writer);

    let mut batch: PendingBatch = HashMap::new();
    let mut in_batch = false;
    // Set when the open batch lost its overlay (a failed SMT_UPDATE, a panicked task): it
    // holds none of the writes the client queued, so it stays open, refusing every command
    // but PING, STATS and BATCH_ABORT, until the client aborts it. Closing it instead let a
    // client that carried on past the error have each later write committed on its own,
    // and only learn of it at BATCH_COMMIT ("no batch is open").
    let mut batch_failed = false;
    let mut payload = Vec::with_capacity(1024);

    /// Writes a response; evaluates to `return` on a broken pipe so a dead
    /// client tears the task down immediately.
    macro_rules! respond {
        ($status:expr, $body:expr) => {
            if write_response(&mut writer, $status, $body).await.is_err() {
                return;
            }
        };
    }

    /// Takes the writer lock for a write (see `WriterLock`), or answers `BUSY` and
    /// moves on to the next request. Inside a batch this connection holds it already.
    macro_rules! claim_writer {
        () => {
            if !writers.acquire(id) {
                respond!(ST_BUSY, b"another connection is writing");
                continue;
            }
        };
    }

    /// Runs a blocking store operation, moving the batch overlay in and back out.
    ///
    /// On a panic the overlay is not recovered, so the batch is abandoned rather
    /// than silently continuing from indeterminate state.
    macro_rules! with_store {
        ($snapshotted:expr, $work:expr) => {{
            let pending = std::mem::take(&mut batch);
            let db2 = Arc::clone(&db);
            let tree2 = Arc::clone(&tree);
            let batched = in_batch;
            let snapshotted = $snapshotted;
            let joined = tokio::task::spawn_blocking(move || {
                // Built here rather than passed in: a closure cannot express that
                // the returned store borrows its `&DB` argument.
                let mut store = if snapshotted {
                    RocksStore::snapshotted(&db2, pending, batched)
                } else {
                    RocksStore::new(&db2, pending, batched)
                };
                #[allow(clippy::redundant_closure_call)]
                let outcome = ($work)(&tree2, &mut store);
                (store.into_overlay(), outcome)
            })
            .await;

            match joined {
                Ok((pending, outcome)) => {
                    batch = pending;
                    Some(outcome)
                }
                Err(e) => {
                    error!("blocking task panicked: {}", e);
                    // Outside a batch there was nothing to lose; inside one, the overlay
                    // went with the task (see `batch_failed`).
                    batch_failed = in_batch;
                    respond!(ST_ERROR, b"internal error");
                    None
                }
            }
        }};
    }

    loop {
        // A write outside a batch held the writer lock for that one request only; a
        // batch holds it until it is committed or aborted.
        if !in_batch {
            writers.release(id);
        }

        // Only the wait for the *next* request is cancellable. A request already
        // read is processed to completion, so shutdown never truncates work in
        // progress — it just stops us accepting more of it.
        let opcode = tokio::select! {
            biased;
            _ = shutdown.recv() => return,
            read = read_request(&mut reader, &mut payload, settings.max_input_size) => match read {
                Ok(Some(op)) => op,
                Ok(None) => return, // clean disconnect
                Err(e) => {
                    error!("protocol read error: {}", e);
                    return;
                }
            },
            // Never inside a batch: its client may be waiting on slow work of its own.
            () = idle_expiry(if in_batch { None } else { settings.idle_timeout }) => {
                debug!("closing an idle connection");
                return;
            }
        };

        // Release the allocation after an unusually large frame rather than
        // pinning it for the lifetime of the connection.
        if payload.capacity() > 64 * 1024 {
            payload.shrink_to(8192);
        }

        // A failed batch (see `batch_failed`): a write would be queued after writes that are
        // gone, and a read would answer from the committed state, which is not the batch's.
        if batch_failed && !matches!(opcode, OP_PING | OP_STATS | OP_BATCH_ABORT) {
            respond!(ST_ERROR, b"the batch failed: abort it");
            continue;
        }

        match opcode {
            // ---------------------------------------------------------
            OP_PING => respond!(ST_OK, b""),

            OP_STATS => {
                let db2 = Arc::clone(&db);
                match tokio::task::spawn_blocking(move || collect_stats(&db2)).await {
                    Ok(s) => respond!(ST_OK, s.as_bytes()),
                    Err(e) => {
                        error!("stats task panicked: {}", e);
                        respond!(ST_ERROR, b"internal error");
                    }
                }
            }

            // ---------------------------------------------------------
            // Raw key/value access, retained for maintenance and debugging.
            // The SMT commands below are what clients use in normal operation.
            OP_GET => {
                let key = payload.clone();
                let Some(outcome) = with_store!(
                    false,
                    move |_t: &Smt, s: &mut RocksStore<'_>| s.get_raw(&key)
                ) else {
                    continue;
                };
                match outcome {
                    Ok(Some(v)) => respond!(ST_OK, &v),
                    Ok(None) => respond!(ST_NOT_FOUND, b""),
                    Err(e) => {
                        error!("get failed: {}", e);
                        respond!(ST_ERROR, e.to_string().as_bytes());
                    }
                }
            }

            OP_PUT => {
                let Some((key, value)) =
                    split_len_prefixed(&payload).map(|(k, v)| (k.to_vec(), v.to_vec()))
                else {
                    respond!(ST_BAD_COMMAND, b"expected [u32 keylen][key][value]");
                    continue;
                };
                if in_tree_keyspace(&key) {
                    respond!(ST_BAD_COMMAND, b"a key of the tree: written by SMT_UPDATE only");
                    continue;
                }
                if in_batch && batch.len() >= settings.max_batch_entries {
                    respond!(ST_BATCH_TOO_LARGE, b"");
                    continue;
                }
                claim_writer!();
                let queued = in_batch;
                let Some(outcome) = with_store!(
                    false,
                    move |_t: &Smt, s: &mut RocksStore<'_>| s.put_raw(key, value)
                ) else {
                    continue;
                };
                match outcome {
                    Ok(()) => respond!(if queued { ST_QUEUED } else { ST_OK }, b""),
                    Err(e) => {
                        error!("put failed: {}", e);
                        respond!(ST_ERROR, e.to_string().as_bytes());
                    }
                }
            }

            OP_DELETE => {
                let key = payload.clone();
                if in_tree_keyspace(&key) {
                    respond!(ST_BAD_COMMAND, b"a key of the tree: written by SMT_UPDATE only");
                    continue;
                }
                if in_batch && batch.len() >= settings.max_batch_entries {
                    respond!(ST_BATCH_TOO_LARGE, b"");
                    continue;
                }
                claim_writer!();
                let queued = in_batch;
                let Some(outcome) = with_store!(
                    false,
                    move |_t: &Smt, s: &mut RocksStore<'_>| s.delete_raw(key)
                ) else {
                    continue;
                };
                match outcome {
                    Ok(()) => respond!(if queued { ST_QUEUED } else { ST_OK }, b""),
                    Err(e) => {
                        error!("delete failed: {}", e);
                        respond!(ST_ERROR, e.to_string().as_bytes());
                    }
                }
            }

            // ---------------------------------------------------------
            OP_SMT_ROOT => {
                let Some(outcome) = with_store!(
                    false,
                    |t: &Smt, s: &mut RocksStore<'_>| t.root(s)
                ) else {
                    continue;
                };
                match outcome {
                    Ok(root) => respond!(ST_OK, &root),
                    Err(e) => {
                        error!("smt root failed: {}", e);
                        respond!(ST_ERROR, e.to_string().as_bytes());
                    }
                }
            }

            OP_SMT_LEAF => {
                let Some(domain) = parse_domain(&payload).map(str::to_string) else {
                    respond!(ST_BAD_COMMAND, b"expected a non-empty utf-8 domain");
                    continue;
                };
                let Some(outcome) = with_store!(
                    false,
                    move |t: &Smt, s: &mut RocksStore<'_>| t.leaf(s, &domain)
                ) else {
                    continue;
                };
                match outcome {
                    Ok(Some(leaf)) => respond!(ST_OK, &leaf),
                    Ok(None) => respond!(ST_NOT_FOUND, b""),
                    Err(e) => {
                        error!("smt leaf failed: {}", e);
                        respond!(ST_ERROR, e.to_string().as_bytes());
                    }
                }
            }

            // Derives the leaf from the record, writes it, and rehashes the spine.
            // Hashing happens here rather than in the client so the leaf format has
            // a single implementation.
            OP_SMT_UPDATE => {
                let Some((leaf, domain)) = parse_record(&payload).map(|r| {
                    (
                        smt::hash_leaf(
                            r.domain,
                            &r.pubkey,
                            r.target_address,
                            r.price,
                            r.nonce,
                        ),
                        r.domain.to_string(),
                    )
                }) else {
                    respond!(ST_BAD_COMMAND, b"malformed record payload");
                    continue;
                };
                // One update touches the leaf plus every ancestor.
                if in_batch && batch.len() + NODES_PER_UPDATE > settings.max_batch_entries {
                    warn!(
                        limit = settings.max_batch_entries,
                        "batch entry limit reached; client must commit"
                    );
                    respond!(ST_BATCH_TOO_LARGE, b"");
                    continue;
                }
                claim_writer!();
                // An update rewrites the whole spine. Those writes always go
                // through an overlay so they land as one atomic batch — writing
                // them individually would leave the tree structurally corrupt if
                // anything failed part-way up.
                let autocommit = !in_batch;
                let pending = std::mem::take(&mut batch);
                let db2 = Arc::clone(&db);
                let tree2 = Arc::clone(&tree);
                let sync = settings.sync_on_commit;
                // Stored verbatim under the record key so a later proof can hand a
                // blocking domain's full preimage to the circuit.
                let record_payload = payload.clone();

                let joined = tokio::task::spawn_blocking(move || {
                    let mut store = RocksStore::new(&db2, pending, true);
                    let result = tree2.update(&mut store, &domain, &record_payload, leaf);
                    let overlay = store.into_overlay();

                    match result {
                        // Discard a half-written spine rather than leaving it
                        // queued where a later commit could persist it.
                        Err(e) => (PendingBatch::new(), Err(e)),
                        Ok(root) if autocommit => {
                            match store::commit_overlay(&db2, overlay, sync) {
                                Ok(()) => (PendingBatch::new(), Ok(root)),
                                Err(e) => (PendingBatch::new(), Err(store::StoreError::Db(e))),
                            }
                        }
                        Ok(root) => (overlay, Ok(root)),
                    }
                })
                .await;

                match joined {
                    Ok((pending, Ok(root))) => {
                        batch = pending;
                        respond!(ST_OK, &root);
                    }
                    Ok((_, Err(e))) => {
                        // The batch is now indeterminate, so it is failed: a later
                        // BATCH_COMMIT is refused instead of persisting a
                        // partially rewritten spine, and so is every write until the
                        // client aborts it (see `batch_failed`).
                        error!("smt update failed: {}", e);
                        batch_failed = in_batch;
                        respond!(ST_ERROR, e.to_string().as_bytes());
                    }
                    Err(e) => {
                        error!("update task panicked: {}", e);
                        batch_failed = in_batch;
                        respond!(ST_ERROR, b"internal error");
                    }
                }
            }

            // True only if the stored leaf equals the hash of the supplied record —
            // the whole of `verifyDomainState` in one round trip, with no leaf
            // hashing on the client.
            OP_SMT_VERIFY => {
                let Some((expected, domain)) = parse_record(&payload).map(|r| {
                    (
                        smt::hash_leaf(
                            r.domain,
                            &r.pubkey,
                            r.target_address,
                            r.price,
                            r.nonce,
                        ),
                        r.domain.to_string(),
                    )
                }) else {
                    respond!(ST_BAD_COMMAND, b"malformed record payload");
                    continue;
                };
                let Some(outcome) = with_store!(
                    false,
                    move |t: &Smt, s: &mut RocksStore<'_>| t.leaf(s, &domain)
                ) else {
                    continue;
                };
                match outcome {
                    // `leaf` already treats an empty leaf as absent, matching the
                    // client-side check this replaces.
                    Ok(Some(stored)) if stored == expected => respond!(ST_OK, b""),
                    Ok(_) => respond!(ST_NOT_FOUND, b""),
                    Err(e) => {
                        error!("smt verify failed: {}", e);
                        respond!(ST_ERROR, e.to_string().as_bytes());
                    }
                }
            }

            // Root and proof together, from one snapshot, so they can never
            // describe different states of the tree.
            OP_SMT_PROOF => {
                let Some(domain) = parse_domain(&payload).map(str::to_string) else {
                    respond!(ST_BAD_COMMAND, b"expected a non-empty utf-8 domain");
                    continue;
                };
                let Some(outcome) = with_store!(
                    true,
                    move |t: &Smt, s: &mut RocksStore<'_>| {
                        let root = t.root(s)?;
                        let proof = t.proof(s, &domain)?;
                        Ok::<_, store::StoreError>((root, proof))
                    }
                ) else {
                    continue;
                };
                match outcome {
                    Ok((root, proof)) => {
                        respond!(ST_OK, &protocol::encode_proof(&root, &proof));
                    }
                    Err(e) => {
                        error!("smt proof failed: {}", e);
                        respond!(ST_ERROR, e.to_string().as_bytes());
                    }
                }
            }

            // Proofs of several domains and their one root, all from one snapshot:
            // a list of names answered together is proved against one state of the
            // tree, in one round trip and one blocking task instead of one each.
            OP_SMT_PROOFS => {
                let Some(domains) = parse_domains(&payload, MAX_PROOFS_PER_REQUEST) else {
                    respond!(
                        ST_BAD_COMMAND,
                        b"expected 1 to 1000 length-prefixed non-empty utf-8 domains"
                    );
                    continue;
                };
                let Some(outcome) = with_store!(
                    true,
                    move |t: &Smt, s: &mut RocksStore<'_>| {
                        let root = t.root(s)?;
                        let mut proofs = Vec::with_capacity(domains.len());
                        for domain in &domains {
                            proofs.push(t.proof(s, domain)?);
                        }
                        Ok::<_, store::StoreError>((root, proofs))
                    }
                ) else {
                    continue;
                };
                match outcome {
                    Ok((root, proofs)) => {
                        respond!(ST_OK, &protocol::encode_proofs(&root, &proofs));
                    }
                    Err(e) => {
                        error!("smt proofs failed: {}", e);
                        respond!(ST_ERROR, e.to_string().as_bytes());
                    }
                }
            }

            // ---------------------------------------------------------
            OP_BATCH_START => {
                // Silently resetting an open batch would discard the client's
                // queued writes behind a success response.
                if in_batch {
                    warn!("BATCH_START received while a batch is already open");
                    respond!(ST_ALREADY_IN_BATCH, b"");
                    continue;
                }
                claim_writer!();
                in_batch = true;
                batch.clear();
                respond!(ST_OK, b"");
            }

            OP_BATCH_COMMIT => {
                if !in_batch {
                    respond!(ST_BAD_COMMAND, b"no batch is open");
                    continue;
                }

                let pending = std::mem::take(&mut batch);
                let db2 = Arc::clone(&db);
                let sync = settings.sync_on_commit;
                let entries = pending.len();

                let res =
                    tokio::task::spawn_blocking(move || store::commit_overlay(&db2, pending, sync))
                        .await;

                in_batch = false;

                match res {
                    Ok(Ok(())) => {
                        info!(entries, sync, "batch committed");
                        respond!(ST_OK, b"");
                    }
                    Ok(Err(e)) => {
                        error!(entries, "rocksdb batch commit failed: {}", e);
                        respond!(ST_ERROR, e.to_string().as_bytes());
                    }
                    Err(e) => {
                        error!("commit task panicked: {}", e);
                        respond!(ST_ERROR, b"internal error");
                    }
                }
            }

            OP_BATCH_ABORT => {
                if !in_batch {
                    respond!(ST_BAD_COMMAND, b"no batch is open");
                    continue;
                }
                batch.clear();
                in_batch = false;
                batch_failed = false;
                info!("batch aborted by client");
                respond!(ST_OK, b"");
            }

            // ---------------------------------------------------------
            OP_CLEAR => {
                // Wiping while a batch is open would silently drop the client's
                // queued writes.
                if in_batch {
                    warn!("CLEAR refused: a batch is open on this connection");
                    respond!(ST_BAD_COMMAND, b"a batch is open");
                    continue;
                }
                // Wiping under another connection's open batch would leave that batch's
                // spines over a tree that is gone.
                claim_writer!();

                warn!("CLEAR requested — wiping the database");
                let db2 = Arc::clone(&db);
                let res = tokio::task::spawn_blocking(move || clear_db(&db2)).await;

                match res {
                    Ok(Ok(())) => {
                        info!("database wiped");
                        respond!(ST_OK, b"");
                    }
                    Ok(Err(e)) => {
                        error!("rocksdb clear failed: {}", e);
                        respond!(ST_ERROR, e.to_string().as_bytes());
                    }
                    Err(e) => {
                        error!("clear task panicked: {}", e);
                        respond!(ST_ERROR, b"internal error");
                    }
                }
            }

            // ---------------------------------------------------------
            // Always answers, so the client's request/response lockstep can
            // never desynchronise.
            other => {
                warn!(opcode = format!("0x{other:02x}"), "unknown opcode");
                respond!(ST_BAD_COMMAND, b"unknown opcode");
            }
        }
    }
}

/// Accepts connections until `shutdown` fires, each on its own task holding one of
/// `connections`' permits. One past the limit is closed at once.
///
/// Returning drops the listener, so nothing more is accepted while the connections
/// already open drain (see `drain`).
async fn serve(
    listener: UnixListener,
    shared: Shared,
    connections: Arc<Semaphore>,
    limit: usize,
    mut shutdown: broadcast::Receiver<()>,
    conn_tx: broadcast::Sender<()>,
) {
    loop {
        // Subscribed before the accept, not once it returns: a receiver sees only what is
        // sent after it exists, so one made after a shutdown signal sent in between would
        // never see it, and its connection would hold the drain below until it timed out.
        let conn_shutdown = conn_tx.subscribe();
        tokio::select! {
            _ = shutdown.recv() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((socket, _)) => {
                        let permit = match Arc::clone(&connections).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                // Dropping the socket closes it, so the client
                                // sees a refusal rather than an indefinite hang.
                                warn!(limit, "connection limit reached; rejecting");
                                continue;
                            }
                        };
                        let shared = shared.clone();
                        tokio::spawn(async move {
                            handle_connection(socket, shared, conn_shutdown).await;
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        // Back off: a persistent error such as EMFILE would otherwise
                        // spin this loop at full speed and flood the log.
                        error!("Socket accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

/// Waits up to `within` for every connection's permit to come back - for every
/// connection task to have finished. True if they all did.
async fn drain(connections: &Semaphore, limit: usize, within: Duration) -> bool {
    // `validate_config` caps the limit at 65536, so it fits.
    let permits = u32::try_from(limit).unwrap_or(u32::MAX);
    tokio::time::timeout(within, connections.acquire_many(permits))
        .await
        .is_ok()
}

// =====================================================================
// 5. MAIN APPLICATION ENTRY POINT
// =====================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = load_config(&cli.config);

    let socket_mode = match validate_config(&config) {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("FATAL: invalid configuration: {}", e);
            std::process::exit(1);
        }
    };
    if let Err(e) = init_logging(&config.logging) {
        eprintln!("FATAL: {}", e);
        std::process::exit(1);
    }

    info!("Starting rr-proxy...");
    info!("Loaded configuration from {}", cli.config);

    // ---- Database ----
    let db = match open_db(&config) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            error!(
                "FATAL: Failed to open RocksDB at {}: {}",
                config.database.db_path, e
            );
            // Point at the actual cause rather than offering an unrelated fix.
            let detail = e.to_string();
            if detail.contains("LOCK") {
                error!("(another rr-proxy instance is already using this database)");
            } else if detail.contains("does not exist") {
                error!("(set database.create_if_missing = true for first-run initialisation)");
            }
            std::process::exit(1);
        }
    };
    info!("RocksDB opened at {}", config.database.db_path);

    // The tree itself is stateless (the compact tree holds no precomputed hashes); one
    // shared instance serves every connection.
    let tree = Arc::new(Smt::new());

    // ---- Socket ----
    let socket_path = Path::new(&config.server.socket_path);

    let listener = match bind_socket(socket_path, socket_mode) {
        Ok(l) => l,
        Err(e) => {
            error!("FATAL: {}", e);
            std::process::exit(1);
        }
    };
    info!(
        "rr-proxy is listening on {} (mode {:o})",
        socket_path.display(),
        socket_mode
    );

    let idle_secs = config
        .tuning
        .idle_timeout_secs
        .unwrap_or(DEFAULT_IDLE_SECS);
    let settings = Settings {
        max_input_size: config.tuning.max_input_size,
        sync_on_commit: config.tuning.sync_on_commit.unwrap_or(true),
        max_batch_entries: config.tuning.max_batch_entries.unwrap_or(1_000_000),
        idle_timeout: (idle_secs > 0).then(|| Duration::from_secs(idle_secs)),
    };
    let shared = Shared {
        db: Arc::clone(&db),
        tree,
        writers: Arc::new(WriterLock::default()),
        settings,
    };

    // ---- Graceful shutdown ----
    // Signals break the accept loop so that main returns normally, running
    // destructors and flushing RocksDB rather than exiting mid-flight.
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let conn_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                error!("cannot listen for SIGTERM: {}", e);
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                error!("cannot listen for SIGINT: {}", e);
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM (systemd stop). Shutting down..."),
            _ = sigint.recv()  => info!("Received SIGINT (Ctrl+C). Shutting down..."),
        }
        let _ = shutdown_tx.send(());
    });

    // ---- Accept loop ----
    // Permits bound concurrency, and double as the drain mechanism: reacquiring
    // all of them at shutdown means every connection task has finished.
    let max_connections = config
        .tuning
        .max_connections
        .unwrap_or(DEFAULT_MAX_CONNECTIONS);
    let connections = Arc::new(Semaphore::new(max_connections));

    serve(
        listener,
        shared,
        Arc::clone(&connections),
        max_connections,
        shutdown_rx,
        conn_tx,
    )
    .await;

    // ---- Clean shutdown ----
    // Connections were signalled by the same broadcast that broke the accept
    // loop; idle ones close at once, and any request already read is processed
    // to completion first. Wait for the permits to come back.
    let drain_secs = config
        .tuning
        .shutdown_drain_secs
        .unwrap_or(DEFAULT_DRAIN_SECS);
    info!(drain_secs, "Draining client connections...");
    if drain(&connections, max_connections, Duration::from_secs(drain_secs)).await {
        info!("All connections closed.");
    } else {
        warn!("Drain timed out; closing with connections still open.");
    }

    info!("Flushing RocksDB...");
    let db_flush = Arc::clone(&db);
    match tokio::task::spawn_blocking(move || db_flush.flush()).await {
        Ok(Ok(())) => {}
        // Not fatal: what was committed is in the WAL, replayed at the next open.
        Ok(Err(e)) => error!("RocksDB flush failed: {}", e),
        Err(e) => error!("flush task panicked: {}", e),
    }

    match remove_stale_socket(socket_path) {
        Ok(()) => info!("Socket file removed."),
        Err(e) => warn!("{}", e),
    }

    drop(db);
    info!("Exited gracefully.");
    Ok(())
}

// =====================================================================
// 6. TESTS
// =====================================================================
//
// Wire-format tests live in `protocol.rs`, tree tests in `smt.rs`, and storage
// tests in `store.rs`. What remains here is configuration handling, and in
// `connection_tests` what a client sees of the connection loop.

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config(input_size: usize, perms: &str) -> Config {
        Config {
            server: ServerConfig {
                socket_path: "/tmp/x.sock".into(),
                socket_perms: perms.into(),
            },
            logging: LoggingConfig::default(),
            database: DatabaseConfig {
                db_path: "/tmp/db".into(),
                create_if_missing: None,
            },
            tuning: TuningConfig {
                max_background_jobs: 4,
                write_buffer_size_mb: 64,
                max_open_files: 10_000,
                max_input_size: input_size,
                block_cache_size_mb: None,
                sync_on_commit: None,
                max_batch_entries: None,
                max_connections: None,
                shutdown_drain_secs: None,
                idle_timeout_secs: None,
            },
        }
    }

    #[test]
    fn accepts_a_valid_config() {
        assert_eq!(validate_config(&sample_config(1024, "0660")).unwrap(), 0o660);
    }

    #[test]
    fn rejects_zero_input_size() {
        // Would make every read fail.
        assert!(validate_config(&sample_config(0, "0660")).is_err());
    }

    #[test]
    fn rejects_non_octal_permissions() {
        // Previously ignored, silently leaving umask defaults on the socket.
        assert!(validate_config(&sample_config(1024, "rw-rw----")).is_err());
        assert!(validate_config(&sample_config(1024, "0o660")).is_err());
    }

    #[test]
    fn rejects_empty_socket_path() {
        let mut c = sample_config(1024, "0660");
        c.server.socket_path = String::new();
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn rejects_zero_batch_limit() {
        let mut c = sample_config(1024, "0660");
        c.tuning.max_batch_entries = Some(0);
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn rejects_zero_connection_limit() {
        // Would accept the socket and then refuse every client.
        let mut c = sample_config(1024, "0660");
        c.tuning.max_connections = Some(0);
        assert!(validate_config(&c).is_err());
    }
}

#[cfg(test)]
mod connection_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn settings(max_batch_entries: usize) -> Settings {
        Settings {
            max_input_size: 1 << 20,
            sync_on_commit: false,
            max_batch_entries,
            idle_timeout: None,
        }
    }

    /// A client of `handle_connection` over a socket pair, with its own database in a
    /// temporary directory, removed when the client that made it is dropped.
    struct Client {
        stream: UnixStream,
        db: Arc<DB>,
        shared: Shared,
        /// `None` on a second connection (`another`): the first one owns the directory.
        path: Option<std::path::PathBuf>,
        // Held so the connection is never told to shut down.
        _shutdown: broadcast::Sender<()>,
    }

    impl Client {
        fn start(tag: &str) -> Client {
            Client::start_with(tag, settings(10_000))
        }

        fn start_with(tag: &str, settings: Settings) -> Client {
            let path = std::env::temp_dir().join(format!("rr-proxy-conn-{}-{}", tag, std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            let db = Arc::new(DB::open_default(&path).unwrap());
            let shared = Shared {
                db: Arc::clone(&db),
                tree: Arc::new(Smt::new()),
                writers: Arc::new(WriterLock::default()),
                settings,
            };
            Client::connect(shared, Some(path))
        }

        /// A second connection to the same database (and writer lock).
        fn another(&self) -> Client {
            Client::connect(self.shared.clone(), None)
        }

        fn connect(shared: Shared, path: Option<std::path::PathBuf>) -> Client {
            let (stream, server) = UnixStream::pair().unwrap();
            let (tx, rx) = broadcast::channel(1);
            tokio::spawn(handle_connection(server, shared.clone(), rx));
            Client { stream, db: Arc::clone(&shared.db), shared, path, _shutdown: tx }
        }

        async fn call(&mut self, op: u8, payload: &[u8]) -> (u8, Vec<u8>) {
            let mut frame = vec![op];
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.extend_from_slice(payload);
            self.stream.write_all(&frame).await.unwrap();
            let mut head = [0u8; 5];
            self.stream.read_exact(&mut head).await.unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(head[1..].try_into().unwrap()) as usize];
            self.stream.read_exact(&mut body).await.unwrap();
            (head[0], body)
        }

        async fn status(&mut self, op: u8, payload: &[u8]) -> u8 {
            self.call(op, payload).await.0
        }
    }

    impl Drop for Client {
        fn drop(&mut self) {
            if let Some(path) = &self.path {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }

    fn record(domain: &str) -> Vec<u8> {
        record_with_nonce(domain, 1)
    }

    fn record_with_nonce(domain: &str, nonce: u64) -> Vec<u8> {
        protocol::encode_record(&kns_core::LeafRecord {
            domain: domain.to_string(),
            pubkey: [7u8; 32],
            target_address: "ps1abc".to_string(),
            price: 0,
            nonce,
        })
    }

    fn put(key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut p = (key.len() as u32).to_be_bytes().to_vec();
        p.extend_from_slice(key);
        p.extend_from_slice(value);
        p
    }

    /// An SMT_UPDATE that fails inside a batch leaves the batch open but failed: nothing
    /// the client sends after it is written, read or committed until it aborts.
    #[tokio::test]
    async fn a_failed_update_fails_the_batch_until_it_is_aborted() {
        let mut c = Client::start("failed-batch");
        // A root node that does not decode: every update fails on it.
        c.db.put([0u8], b"junk").unwrap();

        assert_eq!(c.status(OP_BATCH_START, b"").await, ST_OK);
        assert_eq!(c.status(OP_PUT, &put(b"\x90queued", b"1")).await, ST_QUEUED);
        let (st, body) = c.call(OP_SMT_UPDATE, &record("a.krgn")).await;
        assert_eq!(st, ST_ERROR, "{}", String::from_utf8_lossy(&body));

        let failed: &[u8] = b"the batch failed: abort it";
        for (op, payload) in [
            (OP_SMT_UPDATE, record("b.krgn")),
            (OP_PUT, put(b"\x90later", b"2")),
            (OP_DELETE, b"\x90queued".to_vec()),
            (OP_GET, b"\x90queued".to_vec()),
            (OP_SMT_ROOT, Vec::new()),
            (OP_SMT_LEAF, b"a.krgn".to_vec()),
            (OP_BATCH_START, Vec::new()),
            (OP_CLEAR, Vec::new()),
            (OP_BATCH_COMMIT, Vec::new()),
        ] {
            assert_eq!(c.call(op, &payload).await, (ST_ERROR, failed.to_vec()), "opcode 0x{op:02x}");
        }
        assert_eq!(c.status(OP_PING, b"").await, ST_OK);
        assert_eq!(c.status(OP_STATS, b"").await, ST_OK);

        assert_eq!(c.status(OP_BATCH_ABORT, b"").await, ST_OK);
        // Nothing of it was written.
        assert_eq!(c.status(OP_GET, b"\x90queued").await, ST_NOT_FOUND);
        assert_eq!(c.status(OP_GET, b"\x90later").await, ST_NOT_FOUND);
        assert!(c.db.get(b"\x90queued").unwrap().is_none());

        // Outside a batch the same failure leaves nothing behind to refuse.
        assert_eq!(c.status(OP_SMT_UPDATE, &record("a.krgn")).await, ST_ERROR);
        assert_eq!(c.status(OP_PUT, &put(b"\x90alone", b"3")).await, ST_OK);
        assert_eq!(c.status(OP_GET, b"\x90alone").await, ST_OK);
        // And a new batch works as ever.
        assert_eq!(c.status(OP_BATCH_START, b"").await, ST_OK);
        assert_eq!(c.status(OP_PUT, &put(b"\x90next", b"4")).await, ST_QUEUED);
        assert_eq!(c.status(OP_BATCH_COMMIT, b"").await, ST_OK);
        assert_eq!(c.db.get(b"\x90next").unwrap().as_deref(), Some(&b"4"[..]));
    }

    /// Raw PUT and DELETE are refused in the tree's key spaces, and only there; GET reads
    /// anything. A refusal inside a batch leaves the batch as it was.
    #[tokio::test]
    async fn raw_writes_stay_out_of_the_tree() {
        let mut c = Client::start("raw-keys");
        assert_eq!(c.status(OP_SMT_UPDATE, &record("a.krgn")).await, ST_OK);
        let root_before = c.call(OP_SMT_ROOT, b"").await.1;

        let refused: &[u8] = b"a key of the tree: written by SMT_UPDATE only";
        let depth_max = u8::try_from(DEPTH).unwrap();
        let record_key = smt::record_key("a.krgn");
        for key in [&[0u8][..], &[1, 0x80], &[depth_max, 0xff], &record_key[..], &[smt::RECORD_PREFIX]] {
            assert_eq!(c.call(OP_PUT, &put(key, b"junk")).await, (ST_BAD_COMMAND, refused.to_vec()), "PUT {key:02x?}");
            assert_eq!(c.call(OP_DELETE, key).await, (ST_BAD_COMMAND, refused.to_vec()), "DELETE {key:02x?}");
        }
        assert_eq!(c.status(OP_GET, &[0u8]).await, ST_OK, "the root node reads");
        assert_eq!(c.status(OP_GET, &record_key).await, ST_OK, "a record reads");
        assert_eq!(c.call(OP_SMT_ROOT, b"").await.1, root_before);

        // Just past the node depths, below the record prefix, and the empty key: not the tree's.
        for key in [&[depth_max + 1][..], &[depth_max + 1, 1, 2], &[smt::RECORD_PREFIX - 1], &[]] {
            assert_eq!(c.status(OP_PUT, &put(key, b"v")).await, ST_OK, "PUT {key:02x?}");
            assert_eq!(c.status(OP_DELETE, key).await, ST_OK, "DELETE {key:02x?}");
        }

        assert_eq!(c.status(OP_BATCH_START, b"").await, ST_OK);
        assert_eq!(c.status(OP_PUT, &put(&[0u8], b"junk")).await, ST_BAD_COMMAND);
        assert_eq!(c.status(OP_SMT_UPDATE, &record("b.krgn")).await, ST_OK);
        assert_eq!(c.status(OP_BATCH_COMMIT, b"").await, ST_OK);
        assert_eq!(c.status(OP_SMT_LEAF, b"b.krgn").await, ST_OK);
    }

    /// An SMT_PROOFS payload: `[u32 length][domain]` per domain.
    fn domains(names: &[&[u8]]) -> Vec<u8> {
        let mut p = Vec::new();
        for name in names {
            p.extend_from_slice(&(name.len() as u32).to_be_bytes());
            p.extend_from_slice(name);
        }
        p
    }

    /// SMT_PROOFS refuses every malformed list, answers up to MAX_PROOFS_PER_REQUEST, and
    /// inside a batch reads the batch.
    #[tokio::test]
    async fn smt_proofs_edges() {
        let mut c = Client::start("proofs");
        let many = |n: usize| {
            let names: Vec<String> = (0..n).map(|i| format!("n{i}.krgn")).collect();
            domains(&names.iter().map(|s| s.as_bytes()).collect::<Vec<_>>())
        };
        let mut past_the_end = domains(&[b"a.krgn"]);
        past_the_end.pop();
        for (name, payload) in [
            ("an empty payload", Vec::new()),
            ("an empty domain", domains(&[b""])),
            ("a short length", vec![0, 0, 1]),
            ("a length past the end", past_the_end),
            ("a domain not utf-8", domains(&[&[0xff, 0xfe]])),
            ("one domain too many", many(MAX_PROOFS_PER_REQUEST + 1)),
        ] {
            assert_eq!(c.status(OP_SMT_PROOFS, &payload).await, ST_BAD_COMMAND, "{name}");
        }
        let (st, body) = c.call(OP_SMT_PROOFS, &many(MAX_PROOFS_PER_REQUEST)).await;
        assert_eq!(st, ST_OK);
        // [root][u32 count]...
        let count = u32::from_be_bytes(body[HASH_LEN..HASH_LEN + 4].try_into().unwrap());
        assert_eq!(count as usize, MAX_PROOFS_PER_REQUEST);

        let empty_root = c.call(OP_SMT_ROOT, b"").await.1;
        assert_eq!(c.status(OP_BATCH_START, b"").await, ST_OK);
        let (_, root) = c.call(OP_SMT_UPDATE, &record("x.krgn")).await;
        let (st, body) = c.call(OP_SMT_PROOFS, &domains(&[b"x.krgn", b"y.krgn"])).await;
        assert_eq!(st, ST_OK);
        assert_eq!(&body[..HASH_LEN], &root[..], "the proofs are against the batch's root");
        assert_eq!(c.call(OP_SMT_ROOT, b"").await.1, root, "and so is SMT_ROOT");
        assert_eq!(c.status(OP_BATCH_ABORT, b"").await, ST_OK);
        assert_eq!(c.call(OP_SMT_ROOT, b"").await.1, empty_root, "an abort drops the batch");
    }

    /// The answers the PHP client (`RustRocksDBProxy`) relies on.
    #[tokio::test]
    async fn contract_with_the_php_client() {
        let mut c = Client::start("contract");
        // smtProofs() falls back to SMT_PROOF on exactly this answer from an older daemon.
        assert_eq!(c.call(OP_SMT_PROOFS + 1, b"").await, (ST_BAD_COMMAND, b"unknown opcode".to_vec()));
        assert_eq!(c.status(OP_BATCH_COMMIT, b"").await, ST_BAD_COMMAND);
        assert_eq!(c.status(OP_BATCH_ABORT, b"").await, ST_BAD_COMMAND);
        assert_eq!(c.status(OP_BATCH_START, b"").await, ST_OK);
        assert_eq!(c.status(OP_BATCH_START, b"").await, ST_ALREADY_IN_BATCH);
        assert_eq!(c.status(OP_CLEAR, b"").await, ST_BAD_COMMAND);
        // A malformed command inside a batch leaves the batch open and working.
        assert_eq!(c.status(OP_SMT_UPDATE, b"short").await, ST_BAD_COMMAND);
        assert_eq!(c.status(OP_SMT_UPDATE, &record("a.krgn")).await, ST_OK);
        assert_eq!(c.status(OP_BATCH_COMMIT, b"").await, ST_OK);
        assert_eq!(c.status(OP_SMT_LEAF, b"a.krgn").await, ST_OK);
        assert_eq!(c.status(OP_SMT_LEAF, b"").await, ST_BAD_COMMAND);
    }

    /// SMT_VERIFY: a match, every kind of mismatch, an absent domain, a malformed record,
    /// and inside a batch the batch's state.
    #[tokio::test]
    async fn smt_verify_answers() {
        let mut c = Client::start("verify");
        assert_eq!(c.status(OP_SMT_UPDATE, &record_with_nonce("a.krgn", 1)).await, ST_OK);
        assert_eq!(c.status(OP_SMT_VERIFY, &record_with_nonce("a.krgn", 1)).await, ST_OK, "match");
        assert_eq!(c.status(OP_SMT_VERIFY, &record_with_nonce("a.krgn", 2)).await, ST_NOT_FOUND, "nonce");
        assert_eq!(c.status(OP_SMT_VERIFY, &record_with_nonce("b.krgn", 1)).await, ST_NOT_FOUND, "absent");
        assert_eq!(c.status(OP_SMT_VERIFY, b"short").await, ST_BAD_COMMAND, "malformed");
        assert_eq!(c.status(OP_SMT_VERIFY, b"").await, ST_BAD_COMMAND, "empty");
        let stored = kns_core::LeafRecord {
            domain: "a.krgn".into(),
            pubkey: [7u8; 32],
            target_address: "ps1abc".into(),
            price: 0,
            nonce: 1,
        };
        for (what, other) in [
            ("pubkey", kns_core::LeafRecord { pubkey: [8u8; 32], ..stored.clone() }),
            ("address", kns_core::LeafRecord { target_address: "ps1abd".into(), ..stored.clone() }),
            ("price", kns_core::LeafRecord { price: 1, ..stored.clone() }),
        ] {
            assert_eq!(c.status(OP_SMT_VERIFY, &protocol::encode_record(&other)).await, ST_NOT_FOUND, "{what}");
        }

        assert_eq!(c.status(OP_BATCH_START, b"").await, ST_OK);
        assert_eq!(c.status(OP_SMT_UPDATE, &record_with_nonce("c.krgn", 5)).await, ST_OK);
        assert_eq!(c.status(OP_SMT_UPDATE, &record_with_nonce("a.krgn", 9)).await, ST_OK);
        assert_eq!(c.status(OP_SMT_VERIFY, &record_with_nonce("c.krgn", 5)).await, ST_OK);
        assert_eq!(c.status(OP_SMT_VERIFY, &record_with_nonce("a.krgn", 9)).await, ST_OK);
        assert_eq!(c.status(OP_SMT_VERIFY, &record_with_nonce("a.krgn", 1)).await, ST_NOT_FOUND);
        assert_eq!(c.status(OP_BATCH_ABORT, b"").await, ST_OK);
        assert_eq!(c.status(OP_SMT_VERIFY, &record_with_nonce("c.krgn", 5)).await, ST_NOT_FOUND);
        assert_eq!(c.status(OP_SMT_VERIFY, &record_with_nonce("a.krgn", 1)).await, ST_OK);
    }

    /// PUT and DELETE past the batch limit are refused without failing the batch, which
    /// still commits exactly what it queued. Outside a batch there is no limit.
    #[tokio::test]
    async fn the_raw_batch_limit_leaves_the_batch_usable() {
        let mut c = Client::start_with("limit-raw", settings(3));
        assert_eq!(c.status(OP_BATCH_START, b"").await, ST_OK);
        for k in [b"\x90a", b"\x90b", b"\x90c"] {
            assert_eq!(c.status(OP_PUT, &put(k, b"v")).await, ST_QUEUED);
        }
        assert_eq!(c.status(OP_PUT, &put(b"\x90d", b"v")).await, ST_BATCH_TOO_LARGE);
        assert_eq!(c.status(OP_DELETE, b"\x90a").await, ST_BATCH_TOO_LARGE);
        assert_eq!(c.status(OP_GET, b"\x90c").await, ST_OK);
        assert_eq!(c.status(OP_BATCH_COMMIT, b"").await, ST_OK);
        assert!(c.db.get(b"\x90c").unwrap().is_some());
        assert!(c.db.get(b"\x90d").unwrap().is_none());
        for k in [b"\x90e", b"\x90f", b"\x90g", b"\x90h"] {
            assert_eq!(c.status(OP_PUT, &put(k, b"v")).await, ST_OK);
        }
    }

    /// The batch limit counts a worst-case update (NODES_PER_UPDATE): exactly one fits a
    /// limit of that size, and a refused update leaves the batch committable.
    #[tokio::test]
    async fn the_update_batch_limit_counts_a_worst_case_update() {
        let mut c = Client::start_with("limit-smt", settings(NODES_PER_UPDATE));
        assert_eq!(c.status(OP_BATCH_START, b"").await, ST_OK);
        let (st, root) = c.call(OP_SMT_UPDATE, &record("a.krgn")).await;
        assert_eq!(st, ST_OK);
        assert_eq!(c.status(OP_SMT_UPDATE, &record("b.krgn")).await, ST_BATCH_TOO_LARGE);
        assert_eq!(c.call(OP_SMT_ROOT, b"").await.1, root);
        assert_eq!(c.status(OP_BATCH_COMMIT, b"").await, ST_OK);
        assert_eq!(c.call(OP_SMT_ROOT, b"").await.1, root);
        assert_eq!(c.status(OP_SMT_LEAF, b"b.krgn").await, ST_NOT_FOUND);

        // One short of the worst case: no update fits in a batch, but outside one it is fine.
        let mut d = Client::start_with("limit-smt-short", settings(NODES_PER_UPDATE - 1));
        assert_eq!(d.status(OP_BATCH_START, b"").await, ST_OK);
        assert_eq!(d.status(OP_SMT_UPDATE, &record("a.krgn")).await, ST_BATCH_TOO_LARGE);
        assert_eq!(d.status(OP_BATCH_ABORT, b"").await, ST_OK);
        assert_eq!(d.call(OP_SMT_UPDATE, &record("a.krgn")).await, (ST_OK, root));
    }

    /// CLEAR removes every key, tree and raw, and the tree rebuilt after it hashes as a
    /// fresh one. An empty or single-key database clears too.
    #[tokio::test]
    async fn clear_wipes_everything_and_the_tree_restarts_from_empty() {
        let mut fresh = Client::start("clear-fresh");
        let empty_root = fresh.call(OP_SMT_ROOT, b"").await.1;
        let only_z = fresh.call(OP_SMT_UPDATE, &record_with_nonce("z.krgn", 3)).await.1;

        let mut c = Client::start("clear");
        for (i, d) in ["a.krgn", "b.krgn", "c.krgn"].iter().enumerate() {
            assert_eq!(c.status(OP_SMT_UPDATE, &record_with_nonce(d, i as u64 + 1)).await, ST_OK);
        }
        assert_eq!(c.status(OP_PUT, &put(b"\x90raw", b"v")).await, ST_OK);
        assert_ne!(c.call(OP_SMT_ROOT, b"").await.1, empty_root);

        assert_eq!(c.status(OP_CLEAR, b"").await, ST_OK);
        assert!(c.db.iterator(IteratorMode::Start).next().is_none(), "no key survives");
        assert_eq!(c.call(OP_SMT_ROOT, b"").await.1, empty_root);
        assert_eq!(c.status(OP_SMT_LEAF, b"a.krgn").await, ST_NOT_FOUND);
        assert_eq!(c.status(OP_GET, b"\x90raw").await, ST_NOT_FOUND);
        assert_eq!(c.status(OP_CLEAR, b"").await, ST_OK, "an empty database");
        assert_eq!(c.call(OP_SMT_UPDATE, &record_with_nonce("z.krgn", 3)).await.1, only_z);
        assert_eq!(c.status(OP_CLEAR, b"").await, ST_OK);
        assert_eq!(c.status(OP_PUT, &put(b"\x90one", b"v")).await, ST_OK);
        assert_eq!(c.status(OP_CLEAR, b"").await, ST_OK, "a single-key database");
        assert!(c.db.iterator(IteratorMode::Start).next().is_none());
    }

    /// One writer at a time: while a connection has a batch open, another's writes are
    /// refused BUSY and change nothing, while its reads see the committed tree. The lock
    /// is free again after the commit, and when a writer's connection closes mid-batch.
    /// Without it the second connection's acknowledged update was lost at the commit.
    #[tokio::test]
    async fn a_second_writer_is_refused_while_a_batch_is_open() {
        let mut a = Client::start("writers");
        let mut b = a.another();
        let empty_root = b.call(OP_SMT_ROOT, b"").await.1;

        assert_eq!(a.status(OP_BATCH_START, b"").await, ST_OK);
        assert_eq!(a.status(OP_SMT_UPDATE, &record("a.krgn")).await, ST_OK);
        let busy = (ST_BUSY, b"another connection is writing".to_vec());
        for (op, payload) in [
            (OP_SMT_UPDATE, record("b.krgn")),
            (OP_PUT, put(b"\x90k", b"v")),
            (OP_DELETE, b"\x90k".to_vec()),
            (OP_CLEAR, Vec::new()),
            (OP_BATCH_START, Vec::new()),
        ] {
            assert_eq!(b.call(op, &payload).await, busy, "opcode 0x{op:02x}");
        }
        // Reads are never refused, and see only what is committed.
        assert_eq!(b.call(OP_SMT_ROOT, b"").await.1, empty_root);
        assert_eq!(b.status(OP_SMT_LEAF, b"a.krgn").await, ST_NOT_FOUND);
        assert_eq!(b.status(OP_PING, b"").await, ST_OK);
        // The writer itself is not refused anything.
        assert_eq!(a.status(OP_PUT, &put(b"\x90k", b"v")).await, ST_QUEUED);
        assert_eq!(a.status(OP_BATCH_COMMIT, b"").await, ST_OK);
        assert!(b.db.get(b"\x90k").unwrap().is_some());

        // Free again: b's update lands on top of a's, as through one connection.
        let (st, root) = b.call(OP_SMT_UPDATE, &record("b.krgn")).await;
        assert_eq!(st, ST_OK);
        let mut reference = Client::start("writers-ref");
        reference.call(OP_SMT_UPDATE, &record("a.krgn")).await;
        assert_eq!(reference.call(OP_SMT_UPDATE, &record("b.krgn")).await.1, root);
        assert_eq!(a.status(OP_SMT_LEAF, b"b.krgn").await, ST_OK);

        // A writer that goes away mid-batch frees the lock; its batch is dropped.
        let mut c = a.another();
        assert_eq!(c.status(OP_BATCH_START, b"").await, ST_OK);
        assert_eq!(c.status(OP_SMT_UPDATE, &record("c.krgn")).await, ST_OK);
        assert_eq!(b.status(OP_SMT_UPDATE, &record("d.krgn")).await, ST_BUSY);
        drop(c);
        let mut freed = false;
        for _ in 0..200 {
            match b.status(OP_SMT_UPDATE, &record("d.krgn")).await {
                ST_OK => {
                    freed = true;
                    break;
                }
                st => {
                    assert_eq!(st, ST_BUSY);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        assert!(freed, "the lock is freed when its connection closes");
        assert_eq!(b.status(OP_SMT_LEAF, b"c.krgn").await, ST_NOT_FOUND);
    }

    /// A connection that sends nothing past the idle limit is closed, but never while it
    /// has a batch open.
    #[tokio::test]
    async fn an_idle_connection_is_closed_but_not_inside_a_batch() {
        let idle = Duration::from_secs(1);
        let mut c = Client::start_with(
            "idle",
            Settings {
                idle_timeout: Some(idle),
                ..settings(10_000)
            },
        );
        assert_eq!(c.status(OP_BATCH_START, b"").await, ST_OK);
        tokio::time::sleep(idle * 2).await;
        assert_eq!(c.status(OP_PING, b"").await, ST_OK, "a batch keeps the connection open");
        assert_eq!(c.status(OP_BATCH_ABORT, b"").await, ST_OK);
        tokio::time::sleep(idle * 2).await;
        let mut byte = [0u8; 1];
        assert_eq!(c.stream.read(&mut byte).await.unwrap(), 0, "closed once idle");
    }

    /// The accept loop refuses a connection past the limit, and on shutdown it stops and
    /// the open connections drain.
    #[tokio::test]
    async fn the_connection_limit_refuses_and_shutdown_drains() {
        let dir = std::env::temp_dir().join(format!("rr-proxy-serve-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s.sock");
        let listener = bind_socket(&sock, 0o600).unwrap();
        let db = Arc::new(DB::open_default(dir.join("db")).unwrap());
        let shared = Shared {
            db,
            tree: Arc::new(Smt::new()),
            writers: Arc::new(WriterLock::default()),
            settings: settings(10_000),
        };
        let connections = Arc::new(Semaphore::new(1));
        let (tx, rx) = broadcast::channel(1);
        let server = tokio::spawn(serve(listener, shared, Arc::clone(&connections), 1, rx, tx.clone()));

        let frame = |op: u8| vec![op, 0, 0, 0, 0];
        let mut answer = [0u8; 5];
        let mut first = UnixStream::connect(&sock).await.unwrap();
        first.write_all(&frame(OP_PING)).await.unwrap();
        first.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer[0], ST_OK);

        // The one permit is taken: the next connection is closed without an answer.
        let mut second = UnixStream::connect(&sock).await.unwrap();
        let _ = second.write_all(&frame(OP_PING)).await;
        let mut byte = [0u8; 1];
        assert_eq!(second.read(&mut byte).await.unwrap_or(0), 0, "refused");
        first.write_all(&frame(OP_PING)).await.unwrap();
        first.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer[0], ST_OK, "the first connection still works");

        tx.send(()).unwrap();
        server.await.unwrap();
        assert!(drain(&connections, 1, Duration::from_secs(5)).await, "the idle connection drained");
        assert_eq!(first.read(&mut byte).await.unwrap_or(0), 0, "and was closed");
        assert!(UnixStream::connect(&sock).await.is_err(), "nothing accepts any more");
        let _ = fs::remove_dir_all(&dir);
    }

    /// bind_socket keeps and refuses a regular file at the socket path or its temporary
    /// path, never follows or removes a symlink, and replaces a stale socket.
    #[test]
    fn bind_socket_refuses_what_is_not_a_stale_socket() {
        let dir = std::env::temp_dir().join(format!("rr-proxy-bind-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("x.sock");

        fs::write(&sock, b"keep").unwrap();
        assert!(bind_socket(&sock, 0o660).is_err());
        assert_eq!(fs::read(&sock).unwrap(), b"keep");
        fs::remove_file(&sock).unwrap();

        let tmp = sock.with_extension("binding");
        fs::write(&tmp, b"keep2").unwrap();
        assert!(bind_socket(&sock, 0o660).is_err());
        assert_eq!(fs::read(&tmp).unwrap(), b"keep2");
        fs::remove_file(&tmp).unwrap();

        let target = dir.join("real.sock");
        let _keep = std::os::unix::net::UnixListener::bind(&target).unwrap();
        std::os::unix::fs::symlink(&target, &sock).unwrap();
        assert!(bind_socket(&sock, 0o660).is_err());
        assert!(fs::symlink_metadata(&sock).unwrap().file_type().is_symlink());
        fs::remove_file(&sock).unwrap();

        // bind_socket hands the socket to tokio, which needs a runtime.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let _stale = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            let listener = bind_socket(&sock, 0o640).unwrap();
            let meta = fs::symlink_metadata(&sock).unwrap();
            assert!(meta.file_type().is_socket());
            assert_eq!(meta.permissions().mode() & 0o777, 0o640);
            assert!(fs::symlink_metadata(&tmp).is_err(), "no temporary path is left");
            drop(listener);
        });
        let _ = fs::remove_dir_all(&dir);
    }
}

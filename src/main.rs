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
//! Batches are atomic and provide read-your-own-writes per connection, but the
//! daemon does not isolate concurrent writers. Each tree (indexer, registrar)
//! runs its own instance against its own database, with a single writer each.
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
use tokio::io::{BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

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
}

/// Per-connection settings, cheap to copy into each spawned task.
#[derive(Clone, Copy)]
struct Settings {
    max_input_size: usize,
    sync_on_commit: bool,
    max_batch_entries: usize,
}

/// Ceiling on concurrent connections; also the permit count used to drain them.
const DEFAULT_MAX_CONNECTIONS: usize = 64;
const DEFAULT_DRAIN_SECS: u64 = 15;

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

/// Nodes written per SMT update: the leaf plus one per level up to the root.
/// Worst-case node writes for one update, used only to decide when a client's batch
/// is too large. The compact tree normally touches ~log2(N) nodes, but a split can
/// push two leaves down to the bit where their keys diverge, so the bound stays at
/// the tree depth rather than the expected depth.
const NODES_PER_UPDATE: usize = DEPTH + 1;

async fn handle_connection(
    mut socket: UnixStream,
    db: Arc<DB>,
    tree: Arc<Smt>,
    settings: Settings,
    mut shutdown: broadcast::Receiver<()>,
) {
    let (reader, writer) = socket.split();
    let mut reader = BufReader::new(reader);
    // Buffered so a response header and its payload leave as a single syscall.
    let mut writer = BufWriter::new(writer);

    let mut batch: PendingBatch = HashMap::new();
    let mut in_batch = false;
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
                    in_batch = false;
                    respond!(ST_ERROR, b"internal error");
                    None
                }
            }
        }};
    }

    loop {
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
        };

        // Release the allocation after an unusually large frame rather than
        // pinning it for the lifetime of the connection.
        if payload.capacity() > 64 * 1024 {
            payload.shrink_to(8192);
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
                if in_batch && batch.len() >= settings.max_batch_entries {
                    respond!(ST_BATCH_TOO_LARGE, b"");
                    continue;
                }
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
                if in_batch && batch.len() >= settings.max_batch_entries {
                    respond!(ST_BATCH_TOO_LARGE, b"");
                    continue;
                }
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
                        // The batch is now indeterminate, so close it: a later
                        // BATCH_COMMIT is refused instead of persisting a
                        // partially rewritten spine.
                        error!("smt update failed: {}", e);
                        in_batch = false;
                        respond!(ST_ERROR, e.to_string().as_bytes());
                    }
                    Err(e) => {
                        error!("update task panicked: {}", e);
                        in_batch = false;
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

            // ---------------------------------------------------------
            OP_BATCH_START => {
                // Silently resetting an open batch would discard the client's
                // queued writes behind a success response.
                if in_batch {
                    warn!("BATCH_START received while a batch is already open");
                    respond!(ST_ALREADY_IN_BATCH, b"");
                    continue;
                }
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

    let settings = Settings {
        max_input_size: config.tuning.max_input_size,
        sync_on_commit: config.tuning.sync_on_commit.unwrap_or(true),
        max_batch_entries: config.tuning.max_batch_entries.unwrap_or(1_000_000),
    };

    // ---- Graceful shutdown ----
    // Signals break the accept loop so that main returns normally, running
    // destructors and flushing RocksDB rather than exiting mid-flight.
    let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);
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
    let connections = Arc::new(tokio::sync::Semaphore::new(max_connections));

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((socket, _)) => {
                        let permit = match Arc::clone(&connections).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                // Dropping the socket closes it, so the client
                                // sees a refusal rather than an indefinite hang.
                                warn!(limit = max_connections, "connection limit reached; rejecting");
                                continue;
                            }
                        };
                        let db_clone = Arc::clone(&db);
                        let tree_clone = Arc::clone(&tree);
                        let conn_shutdown = conn_tx.subscribe();
                        tokio::spawn(async move {
                            handle_connection(socket, db_clone, tree_clone, settings, conn_shutdown)
                                .await;
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        // Back off: a persistent error such as EMFILE would otherwise
                        // spin this loop at full speed and flood the log.
                        error!("Socket accept error: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    // ---- Clean shutdown ----
    // Connections were signalled by the same broadcast that broke the accept
    // loop; idle ones close at once, and any request already read is processed
    // to completion first. Wait for the permits to come back.
    let drain_secs = config
        .tuning
        .shutdown_drain_secs
        .unwrap_or(DEFAULT_DRAIN_SECS);
    info!(drain_secs, "Draining client connections...");
    match tokio::time::timeout(
        std::time::Duration::from_secs(drain_secs),
        connections.acquire_many(max_connections as u32),
    )
    .await
    {
        Ok(_) => info!("All connections closed."),
        Err(_) => warn!("Drain timed out; closing with connections still open."),
    }

    info!("Flushing RocksDB...");
    let db_flush = Arc::clone(&db);
    if let Err(e) = tokio::task::spawn_blocking(move || db_flush.flush()).await {
        error!("flush task panicked: {}", e);
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
// tests in `store.rs`. What remains here is configuration handling.

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

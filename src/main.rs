use rocksdb::{BlockBasedOptions, Cache, Options, DB, WriteBatch};
use serde::Deserialize;
use std::collections::HashMap; // <-- NEW: Required for the Shadow Cache
use std::fs;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::signal::unix::{signal, SignalKind};
use tokio::net::UnixListener;
use tracing::{error, info};
use clap::Parser;

// =====================================================================
// 1. COMMAND LINE ARGUMENTS & CONFIGURATION
// =====================================================================

#[derive(Parser, Debug)]
#[command(author, version, about = "PiNS RocksDB Proxy Daemon", long_about = None)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long)]
    config: String,
}

#[derive(Deserialize, Debug)]
struct Config {
    server: ServerConfig,
    database: DatabaseConfig,
    tuning: TuningConfig,
}

#[derive(Deserialize, Debug)]
struct ServerConfig {
    socket_path: String,
    socket_perms: String,
}

#[derive(Deserialize, Debug)]
struct DatabaseConfig {
    db_path: String,
}

#[derive(Deserialize, Debug)]
struct TuningConfig {
    max_background_jobs: i32,
    write_buffer_size_mb: usize,
    max_open_files: i32,
    max_input_size: usize,
    block_cache_size_mb: Option<usize>,
}

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

// =====================================================================
// 2. MAIN APPLICATION ENTRY POINT
// =====================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the tracing subscriber for standardized logging
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    info!("Starting rr-proxy...");

    let config = load_config(&cli.config);
    info!("Loaded configuration from {}", cli.config);

    // =================================================================
    // 3. ROCKSDB INITIALIZATION & TUNING
    // =================================================================
    
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.set_max_background_jobs(config.tuning.max_background_jobs);
    opts.set_write_buffer_size(config.tuning.write_buffer_size_mb * 1024 * 1024);
    opts.set_max_open_files(config.tuning.max_open_files);

    // Optimize lookups with a Bloom Filter and LRU Block Cache
    let cache_size = config.tuning.block_cache_size_mb.unwrap_or(128) * 1024 * 1024;
    let cache = Cache::new_lru_cache(cache_size);
    
    let mut block_opts = BlockBasedOptions::default();
    block_opts.set_block_cache(&cache);
    block_opts.set_bloom_filter(10.0, false); // 10 bits per key, full filter (false for block_based)
    
    opts.set_block_based_table_factory(&block_opts);

    // Wrap the DB instance in an Arc so it can be safely shared across Tokio threads
    let db = match DB::open(&opts, &config.database.db_path) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            error!("FATAL: Failed to open RocksDB at {}: {}", config.database.db_path, e);
            std::process::exit(1);
        }
    };
    info!("RocksDB opened at {}", config.database.db_path);

    // =================================================================
    // 4. UNIX SOCKET LIFECYCLE MANAGEMENT
    // =================================================================
    
    let socket_path = &config.server.socket_path;
    
    // STARTUP CLEANUP: Unconditionally remove the socket file if it exists.
    // This prevents "Address already in use" errors if the daemon previously crashed hard.
    let _ = fs::remove_file(socket_path); 
    
    let listener = UnixListener::bind(socket_path)?;
    
    // Apply strict permissions to the Unix socket for security
    if let Ok(perms) = u32::from_str_radix(&config.server.socket_perms, 8) {
        let _ = fs::set_permissions(socket_path, std::os::unix::fs::PermissionsExt::from_mode(perms));
    }
    
    info!("rr-proxy is listening on {}", socket_path);

    // GRACEFUL SHUTDOWN LISTENER: 
    // Spawns a background task to watch for systemd stops (SIGTERM) or user aborts (SIGINT).
    // Ensures the .sock file is deleted cleanly from the hard drive upon exit.
    let path_clone = socket_path.to_string();
    tokio::spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to bind SIGTERM");
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to bind SIGINT");

        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM (systemd stop). Cleaning up socket...");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT (Ctrl+C). Cleaning up socket...");
            }
        }

        let _ = fs::remove_file(&path_clone);
        info!("Socket file removed. Exiting gracefully.");
        std::process::exit(0);
    });

    // =================================================================
    // HELPER FUNCTIONS FOR PROTOCOL HANDLING
    // =================================================================

    /// Reads from the reader until the delimiter is found, up to the specified limit.
    /// Returns the number of bytes read on success.
    async fn read_until_limited<R: AsyncBufRead + Unpin>(
        reader: &mut R,
        out: &mut Vec<u8>,
        delimiter: u8,
        limit: usize,
    ) -> std::io::Result<usize> {
        out.clear();
        let mut total_bytes = 0;
        loop {
            let buf = reader.fill_buf().await?;
            if buf.is_empty() {
                return Ok(total_bytes);
            }

            let mut chunk_len = 0;
            let mut found_delim = false;
            for &b in buf {
                chunk_len += 1;
                if b == delimiter {
                    found_delim = true;
                    break;
                }
            }

            if total_bytes + chunk_len > limit {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Input line length limit exceeded (max: {} bytes)", limit),
                ));
            }

            out.extend_from_slice(&buf[..chunk_len]);
            total_bytes += chunk_len;

            Pin::new(&mut *reader).consume(chunk_len);

            if found_delim {
                return Ok(total_bytes);
            }
        }
    }

    /// Trims leading and trailing ASCII whitespace from a byte slice.
    fn trim_bytes(mut s: &[u8]) -> &[u8] {
        while let Some((&first, rest)) = s.split_first() {
            if first.is_ascii_whitespace() {
                s = rest;
            } else {
                break;
            }
        }
        while let Some((&last, rest)) = s.split_last() {
            if last.is_ascii_whitespace() {
                s = rest;
            } else {
                break;
            }
        }
        s
    }

    // =================================================================
    // 5. CLIENT CONNECTION & TRANSACTION LOOP
    // =================================================================
    
    let max_input_size = config.tuning.max_input_size;

    // Accept incoming socket connections infinitely
    loop {
        match listener.accept().await {
            Ok((mut socket, _)) => {
                let db_clone = Arc::clone(&db);
                
                // Spawn a dedicated thread for each client connection
                tokio::spawn(async move {
                    let (reader, mut writer) = socket.split();
                    let mut buf_reader = BufReader::new(reader);
                    
                    // --- TRANSACTION STATE FOR THIS CONNECTION ---
                    // `batch` holds the actual writes destined for RocksDB
                    let mut batch = WriteBatch::default();
                    let mut in_batch = false;
                    
                    // `shadow_cache` solves the Read-Your-Own-Writes (RYOW) problem.
                    // It holds uncommitted RAM data so GET requests can read updated tree nodes
                    // before the transaction is officially committed to disk.
                    let mut shadow_cache: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

                    // Pre-allocate a buffer for reading commands to avoid allocation on every iteration.
                    let mut byte_buf = Vec::with_capacity(1024);

                    loop { 
                        // Wait for a command from the PHP client
                        match read_until_limited(&mut buf_reader, &mut byte_buf, b'\n', max_input_size).await {
                            Ok(0) => return, // Client disconnected gracefully, thread ends
                            Ok(_) => {
                                let request = trim_bytes(&byte_buf);
                                let parts: Vec<&[u8]> = request.splitn(3, |&b| b == b'|').collect();
                                if parts.is_empty() || parts[0].is_empty() { continue; }

                                // --- COMMAND ROUTER ---
                                if parts[0] == b"GET" && parts.len() == 2 {
                                    let key = parts[1];
                                    
                                    // 1. Shadow Cache Check (Uncommitted Transaction Data)
                                    if in_batch {
                                        if let Some(cached_val) = shadow_cache.get(key) {
                                            if writer.write_all(cached_val).await.is_err() || writer.write_all(b"\n").await.is_err() {
                                                return; // connection error, exit
                                            }
                                            continue; // Exit this loop iteration early
                                        }
                                    }

                                    // 2. Hard Drive Check (Committed Data)
                                    match db_clone.get(key) {
                                        Ok(Some(value)) => {
                                            if writer.write_all(&value).await.is_err() || writer.write_all(b"\n").await.is_err() {
                                                return;
                                            }
                                        }
                                        Ok(None) => {
                                            if writer.write_all(b"NOT_FOUND\n").await.is_err() {
                                                return;
                                            }
                                        }
                                        Err(_) => {
                                            if writer.write_all(b"ERROR\n").await.is_err() {
                                                return;
                                            }
                                        }
                                    }
                                } 
                                else if parts[0] == b"BATCH_START" {
                                    in_batch = true;
                                    batch = WriteBatch::default(); // Purge old batch
                                    shadow_cache.clear();          // Purge old cache
                                    if writer.write_all(b"OK\n").await.is_err() {
                                        return;
                                    }
                                }
                                else if parts[0] == b"BATCH_COMMIT" {
                                    if in_batch {
                                        // Atomically push all queued updates to the hard drive
                                        match db_clone.write(batch) {
                                            Ok(_) => {
                                                if writer.write_all(b"OK\n").await.is_err() {
                                                    return;
                                                }
                                            }
                                            Err(_) => {
                                                if writer.write_all(b"ERROR\n").await.is_err() {
                                                    return;
                                                }
                                            }
                                        }
                                        // Reset transaction state safely
                                        batch = WriteBatch::default(); 
                                        shadow_cache.clear(); 
                                        in_batch = false;
                                    } else {
                                        if writer.write_all(b"BAD_COMMAND\n").await.is_err() {
                                            return;
                                        }
                                    }
                                }
                                else if parts[0] == b"PUT" && parts.len() == 3 {
                                    let key = parts[1];
                                    let val = parts[2];

                                    if in_batch {
                                        // Queue into the WriteBatch for RocksDB
                                        batch.put(key, val);
                                        // Queue into the Shadow Cache so PHP can read it immediately
                                        shadow_cache.insert(key.to_vec(), val.to_vec());
                                        
                                        if writer.write_all(b"QUEUED\n").await.is_err() {
                                            return;
                                        }
                                    } else {
                                        // If no transaction is active, write straight to disk
                                        match db_clone.put(key, val) {
                                            Ok(_) => {
                                                if writer.write_all(b"OK\n").await.is_err() {
                                                    return;
                                                }
                                            }
                                            Err(_) => {
                                                if writer.write_all(b"ERROR\n").await.is_err() {
                                                    return;
                                                }
                                            }
                                        }
                                    }
                                }
                                // ==========================================
                                // NEW: THE DATABASE WIPE COMMAND (OPTIMIZED)
                                // ==========================================
                                else if parts[0] == b"CLEAR" {
                                    let mut delete_batch = WriteBatch::default();
                                    
                                    // 1. Create an iterator starting from the beginning of the DB
                                    let iter = db_clone.iterator(rocksdb::IteratorMode::Start);

                                    // 2. Loop through every single key-value pair and stage delete
                                    for item in iter {
                                        if let Ok((key, _)) = item {
                                            delete_batch.delete(key);
                                        }
                                    }

                                    // 3. Write deletion batch atomically to disk
                                    let wipe_result = db_clone.write(delete_batch);

                                    // 4. Safely purge any active transaction state in memory
                                    batch = WriteBatch::default();
                                    shadow_cache.clear();
                                    in_batch = false;

                                    match wipe_result {
                                        Ok(_) => {
                                            if writer.write_all(b"OK\n").await.is_err() {
                                                return;
                                            }
                                        }
                                        Err(_) => {
                                            if writer.write_all(b"ERROR\n").await.is_err() {
                                                return;
                                            }
                                        }
                                    }
                                }
                                // ==========================================
                                else {
                                    if writer.write_all(b"BAD_COMMAND\n").await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Socket read error: {}", e);
                                return; // Socket communication error, thread dies safely
                            }
                        }
                    }
                });
            }
            Err(e) => { error!("Socket accept error: {}", e); }
        }
    }
}

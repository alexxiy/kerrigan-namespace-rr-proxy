# Rust RocksDB Proxy (`rr-proxy`)

A lightweight, high-performance Unix socket proxy for RocksDB written in Rust. It is designed to expose RocksDB to environments that lack native thread-safe or high-performance RocksDB bindings (such as PHP), providing fast, concurrent, and transactional access over a Unix domain socket.

## SMT Handling in PIVX.Name Service

This proxy is a core component of the **PIVX.Name Service (PiNS)**, where it handles the underlying storage for the **Sparse Merkle Tree (SMT)**. 

Because Sparse Merkle Trees require generating cryptographic proofs and updating tree structure via thousands of operations per block, they require low-latency reads and writes. Furthermore, during a single tree update sequence, parent nodes must be read immediately after being updated, but before the entire batch is committed. 

To solve this, `rr-proxy` implements a transactional batch mode with a **Shadow Cache** providing **Read-Your-Own-Writes (RYOW)** capability. This allows the client to perform intermediate lookups within a transaction block, retrieving uncommitted values directly from the proxy's memory, before atomically committing the final state to RocksDB.

## Features

- **Asynchronous & Concurrent**: Built on Tokio, spawning dedicated task handlers for concurrent client connections.
- **Transactional Write Batches**: Supports atomic writes using RocksDB `WriteBatch`.
- **Read-Your-Own-Writes (RYOW)**: A temporary transaction-scoped shadow cache allows reading values queued in the current batch before commitment.
- **Tuned for Performance**: Supports configuration for background jobs, write buffer sizes, LRU block cache size, and Bloom Filters to optimize lookup speeds.
- **Graceful Lifecycle Management**: Cleans up socket files upon system shutdowns or process interruption (SIGTERM/SIGINT).

## Socket Protocol

The proxy communicates via a line-based text protocol over a Unix socket. Fields are separated by the pipe character (`|`).

| Command | Arguments | Response | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `<key>` | `<value>` \| `NOT_FOUND` \| `ERROR` | Retrieve the value for a key. If in an active batch, checks the shadow cache first. |
| `PUT` | `<key>\|<value>` | `OK` \| `QUEUED` \| `ERROR` | Put key-value pair. Returns `QUEUED` if in a batch, or writes immediately and returns `OK` if not. |
| `BATCH_START` | None | `OK` | Start a new transaction batch and initialize shadow cache. |
| `BATCH_COMMIT` | None | `OK` \| `ERROR` \| `BAD_COMMAND` | Atomically commit the current batch to disk and close the transaction. |
| `CLEAR` | None | `OK` \| `ERROR` | Wipe all keys from the database and clear active transaction state. |

## Configuration

The proxy is configured via a TOML file. Below is an example configuration file:

```toml
[server]
socket_path = "/run/rr-proxy/rr-proxy.sock"
socket_perms = "0666"

[database]
db_path = "/opt/rr-proxy/db"

[tuning]
max_background_jobs = 4
write_buffer_size_mb = 64
max_open_files = 10000
max_input_size = 16777216
block_cache_size_mb = 128
```

## Running the Proxy

Build the daemon:
```bash
cargo build --release
```

Run manually (note that the `--config` parameter is required):
```bash
./target/release/rr-proxy --config config.toml
```

## Systemd Service Deployment

A systemd service unit template is provided in [contrib/rr-proxy.service](file:///home/alexey/myProjects/my-misc/www/rr_proxy/contrib/rr-proxy.service) to run the proxy as a daemon. 

### Installation Steps

1. Copy the executable to `/opt/rr-proxy/`:
   ```bash
   sudo mkdir -p /opt/rr-proxy
   sudo cp target/release/rr-proxy /opt/rr-proxy/
   ```

2. Copy the configuration file to `/opt/rr-proxy/config.toml` and configure your paths. Ensure the `socket_path` is set to `/run/rr-proxy/rr-proxy.sock`:
   ```bash
   sudo cp config-indexer.toml /opt/rr-proxy/config.toml
   ```

3. Copy the service file to `/etc/systemd/system/`:
   ```bash
   sudo cp contrib/rr-proxy.service /etc/systemd/system/
   ```

4. Edit the `/etc/systemd/system/rr-proxy.service` file to replace `{{USER}}` and `{{GROUP}}` with the appropriate user and group names.
   
5. Reload systemd, enable, and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable rr-proxy
   sudo systemctl start rr-proxy
   ```

> [!NOTE]
> The service utilizes `RuntimeDirectory=rr-proxy` which configures systemd to automatically create `/run/rr-proxy/` (owned by your configured `User`/`Group` with mode `0755` permissions) before launching the binary, and clean it up when the daemon stops.

## License

This project is licensed under the GNU Affero General Public License v3.0. For details, see the [LICENSE](LICENSE) file.

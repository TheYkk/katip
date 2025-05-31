use distributed_journal::broker::server::Server;
use distributed_journal::storage::log::Log; // Corrected import path
use distributed_journal::storage::compaction::CompactionOptions;
// use distributed_journal::Error as DJError; // Removed unused import
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

// Note: The Display and Error traits for DJError are now in lib.rs
// No need to redefine them here if Error is public and correctly implemented there.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let log_dir = std::env::temp_dir().join("distributed_journal_broker_main");
    // Clean up previous run's directory if it exists
    if log_dir.exists() {
       std::fs::remove_dir_all(&log_dir)?;
    }
    std::fs::create_dir_all(&log_dir)?;

    log::info!("Using log directory: {:?}", log_dir);

    let log_instance = Log::new(
        log_dir,
        Some(10 * 1024 * 1024), // 10MB max segment size
        Some(std::time::Duration::from_secs(60 * 60 * 24)), // 1 day max segment duration
        Some(CompactionOptions::default())
    ).map_err(|e| format!("Failed to create Log: {:?}", e))?; // Convert DJError to String error for Box<dyn Error>

    let shared_log = Arc::new(TokioMutex::new(log_instance));

    let server_addr = "127.0.0.1:8080";
    let mut server = Server::new(server_addr, shared_log)
        .await
        .map_err(|e| format!("Failed to create Server: {:?}", e))?;

    log::info!("Starting server on {}...", server_addr);
    server.run().await.map_err(|e| format!("Server run failed: {:?}", e))?;

    Ok(())
}

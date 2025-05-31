// src/broker/server.rs
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as TokioMutex; // Alias to avoid conflict if std::sync::Mutex is also used
use std::sync::Arc;
use crate::storage::Log;
use crate::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // For Handler

// Server struct (shutdown channels are placeholders for now)
pub struct Server {
    listener: TcpListener,
    log: Arc<TokioMutex<Log>>,
    // notify_shutdown: tokio::sync::mpsc::Sender<()>, // Example, not fully used in this step
    // shutdown_complete_rx: tokio::sync::mpsc::Receiver<()>, // Example
}

// Handler for individual client connections
pub struct Handler {
    stream: TcpStream,
    log: Arc<TokioMutex<Log>>,
}

impl Server {
    pub async fn new(addr: &str, log: Arc<TokioMutex<Log>>) -> Result<Self, Error> {
        let listener = TcpListener::bind(addr).await?;
        log::info!("Broker server bound to {}", addr);
        Ok(Server {
            listener,
            log,
            // notify_shutdown and shutdown_complete_rx would be initialized here
        })
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        log::info!("Broker server listening on {}", self.listener.local_addr()?);

        loop {
            // For now, accept loop doesn't have explicit shutdown signal handling.
            match self.listener.accept().await {
                Ok((stream, client_addr)) => {
                    log::info!("Accepted new connection from: {}", client_addr);
                    let log_clone = Arc::clone(&self.log);

                    tokio::spawn(async move {
                        let mut handler = Handler::new(stream, log_clone);
                        if let Err(e) = handler.handle_connection().await {
                            log::error!("Error handling connection from {}: {:?}", client_addr, e);
                        }
                        log::info!("Connection with {} closed.", client_addr);
                    });
                }
                Err(e) => {
                    log::error!("Failed to accept new connection: {:?}", e);
                    // Depending on error, might continue or break. For now, continue.
                }
            }
        }
        // Loop is infinite for now, explicitly.
        // In a real server, this would be structured to allow graceful shutdown.
        // For example, by selecting on listener.accept() and a shutdown signal.
        // Ok(()) // Unreachable if loop is truly infinite without break
    }
}

impl Handler {
    pub fn new(stream: TcpStream, log: Arc<TokioMutex<Log>>) -> Self {
        Handler { stream, log }
    }

    pub async fn handle_connection(&mut self) -> Result<(), Error> {
        let mut buffer = [0; 1024];
        loop {
            match self.stream.read(&mut buffer).await {
                Ok(0) => {
                    log::info!("Client closed connection (EOF).");
                    return Ok(());
                }
                Ok(n) => {
                    let received_data = &buffer[..n];
                    log::info!("Received {} bytes: '{}'", n, String::from_utf8_lossy(received_data));

                    // Placeholder: Actual log interaction would happen here
                    // let mut log_guard = self.log.lock().await;
                    // log_guard.append(received_data.to_vec(), b"some_value".to_vec())?;
                    // drop(log_guard);


                    if let Err(e) = self.stream.write_all(b"ACK\n").await {
                        log::error!("Failed to write acknowledgment: {:?}", e);
                        return Err(Error::Io(e));
                    }
                }
                Err(e) => {
                    log::error!("Error reading from stream: {:?}", e);
                    return Err(Error::Io(e));
                }
            }
        }
    }
}

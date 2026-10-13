use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Error, Debug)]
pub enum PingError {
    #[error("TCP ping timed out")]
    Timeout,
    #[error("TCP ping connection failed: {0}")]
    Io(#[from] std::io::Error),
}

pub async fn measure_tcp_latency(
    host: &str,
    port: u16,
    max_timeout: Duration,
) -> Result<u64, PingError> {
    let addr = format!("{}:{}", host, port);
    let start = Instant::now();

    match timeout(max_timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => {
            let elapsed = start.elapsed().as_millis() as u64;
            Ok(elapsed)
        }
        Ok(Err(e)) => Err(PingError::Io(e)),
        Err(_) => Err(PingError::Timeout),
    }
}

use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct TunneledStream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    read_buf: Option<Bytes>,
    metrics: Option<std::sync::Arc<crate::tunnel::h2_session::TrafficMetrics>>,
}

impl TunneledStream {
    pub fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            read_buf: None,
            metrics: None,
        }
    }

    pub fn new_with_metrics(
        recv: RecvStream,
        send: SendStream<Bytes>,
        metrics: Option<std::sync::Arc<crate::tunnel::h2_session::TrafficMetrics>>,
    ) -> Self {
        Self {
            recv,
            send,
            read_buf: None,
            metrics,
        }
    }
}

impl AsyncRead for TunneledStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(mut remaining) = self.read_buf.take() {
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            if let Some(ref m) = self.metrics {
                m.bytes_rx
                    .fetch_add(to_copy as u64, std::sync::atomic::Ordering::Relaxed);
            }
            // Release capacity only as bytes are consumed into caller's buffer
            let _ = self.recv.flow_control().release_capacity(to_copy);
            if to_copy < remaining.len() {
                remaining.advance(to_copy);
                self.read_buf = Some(remaining);
            }
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.recv).poll_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(Some(Ok(bytes))) => {
                let to_copy = std::cmp::min(bytes.len(), buf.remaining());
                buf.put_slice(&bytes[..to_copy]);
                if let Some(ref m) = self.metrics {
                    m.bytes_rx
                        .fetch_add(to_copy as u64, std::sync::atomic::Ordering::Relaxed);
                }
                let _ = self.recv.flow_control().release_capacity(to_copy);
                if to_copy < bytes.len() {
                    self.read_buf = Some(bytes.slice(to_copy..));
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for TunneledStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        self.send.reserve_capacity(buf.len());
        match self.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H2 stream closed",
            ))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(Some(Ok(avail))) => {
                let to_send = std::cmp::min(avail, buf.len());
                let data = Bytes::copy_from_slice(&buf[..to_send]);
                self.send.send_data(data, false).map_err(io::Error::other)?;
                if let Some(ref m) = self.metrics {
                    m.bytes_tx
                        .fetch_add(to_send as u64, std::sync::atomic::Ordering::Relaxed);
                }
                Poll::Ready(Ok(to_send))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

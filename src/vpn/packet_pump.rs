use crate::tunnel::h2_session::H2UpstreamSession;
use crate::vpn::netstack::VirtualNetstack;
use crate::vpn::wintun_adapter::WintunDevice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub struct PacketPump {
    running: Arc<AtomicBool>,
    netstack: Arc<tokio::sync::Mutex<Option<Arc<VirtualNetstack>>>>,
}

impl PacketPump {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            netstack: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub fn start(
        &self,
        device: Arc<WintunDevice>,
        upstream: Arc<H2UpstreamSession>,
    ) -> JoinHandle<()> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Vec<u8>>(2048);

        let netstack = Arc::new(VirtualNetstack::new(device.ip, upstream, outbound_tx));
        netstack.start_reaper();

        let netstack_ref = self.netstack.clone();
        let netstack_for_worker = netstack.clone();

        tokio::spawn(async move {
            *netstack_ref.lock().await = Some(netstack.clone());

            let dev_writer = device.clone();
            let running_writer = running.clone();

            // Task 1: Outbound writer (Netstack -> Wintun)
            let writer_handle = tokio::task::spawn_blocking(move || {
                let session = &dev_writer.session;
                while running_writer.load(Ordering::SeqCst) {
                    match outbound_rx.blocking_recv() {
                        Some(pkt) => {
                            if let Ok(mut send_pkt) = session.allocate_send_packet(pkt.len() as u16)
                            {
                                send_pkt.bytes_mut().copy_from_slice(&pkt);
                                session.send_packet(send_pkt);
                            }
                        }
                        None => break,
                    }
                }
            });

            // Task 2: Inbound reader (Wintun -> Inbound Channel)
            let dev_reader = device.clone();
            let running_reader = running.clone();
            let inbound_tx_clone = inbound_tx.clone();

            let reader_handle = tokio::task::spawn_blocking(move || {
                let session = &dev_reader.session;

                while running_reader.load(Ordering::SeqCst) {
                    match session.receive_blocking() {
                        Ok(packet) => {
                            let bytes = packet.bytes().to_vec();
                            if inbound_tx_clone.blocking_send(bytes).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            if running_reader.load(Ordering::SeqCst) {
                                tracing::warn!("Wintun receive error: {:?}", e);
                            }
                            break;
                        }
                    }
                }
            });

            // Task 3: Inbound sequential dispatcher (Inbound Channel -> Netstack)
            let running_dispatcher = running.clone();
            let dispatcher_handle = tokio::spawn(async move {
                while running_dispatcher.load(Ordering::SeqCst) {
                    match inbound_rx.recv().await {
                        Some(packet) => {
                            netstack_for_worker.handle_packet(&packet).await;
                        }
                        None => break,
                    }
                }
            });

            let _ = tokio::join!(writer_handle, reader_handle, dispatcher_handle);
            tracing::info!("Packet pump fully terminated");
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let netstack_ref = self.netstack.clone();
        tokio::spawn(async move {
            if let Some(ns) = netstack_ref.lock().await.take() {
                ns.stop();
            }
        });
    }
}

impl Default for PacketPump {
    fn default() -> Self {
        Self::new()
    }
}

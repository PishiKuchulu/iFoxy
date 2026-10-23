use crate::tunnel::h2_session::H2UpstreamSession;
use crate::vpn::netstack::VirtualNetstack;
#[cfg(windows)]
use crate::vpn::wintun_adapter::WintunDevice;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// An OS tunnel device the pump moves raw IPv4 packets to and from.
/// Implemented by the Windows Wintun device and the Linux TUN device;
/// both operations are used from blocking worker threads.
pub trait TunDeviceOps: Send + Sync {
    /// The tunnel interface's local IPv4 address (the netstack's identity).
    fn ip(&self) -> Ipv4Addr;
    /// The tunnel interface's OS interface index (routes, kill switch).
    fn adapter_index(&self) -> u32;
    /// Queue one raw IPv4 packet toward the OS. Best-effort: a full or
    /// torn-down device drops the packet, matching the Wintun semantics
    /// this replaces.
    fn send_packet(&self, packet: &[u8]);
    /// Block until one raw IPv4 packet arrives from the OS.
    fn receive_blocking(&self) -> Result<Vec<u8>, String>;
}

#[cfg(windows)]
impl TunDeviceOps for WintunDevice {
    fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    fn adapter_index(&self) -> u32 {
        self.adapter_index
    }

    fn send_packet(&self, packet: &[u8]) {
        if let Ok(mut send_pkt) = self.session.allocate_send_packet(packet.len() as u16) {
            send_pkt.bytes_mut().copy_from_slice(packet);
            self.session.send_packet(send_pkt);
        }
    }

    fn receive_blocking(&self) -> Result<Vec<u8>, String> {
        self.session
            .receive_blocking()
            .map(|packet| packet.bytes().to_vec())
            .map_err(|e| format!("{:?}", e))
    }
}

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
        device: Arc<dyn TunDeviceOps>,
        upstream: Arc<H2UpstreamSession>,
    ) -> JoinHandle<()> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Vec<u8>>(2048);

        let netstack = Arc::new(VirtualNetstack::new(device.ip(), upstream, outbound_tx));
        netstack.start_reaper();

        let netstack_ref = self.netstack.clone();
        let netstack_for_worker = netstack.clone();

        tokio::spawn(async move {
            *netstack_ref.lock().await = Some(netstack.clone());

            let dev_writer = device.clone();
            let running_writer = running.clone();

            // Task 1: Outbound writer (Netstack -> TUN device)
            let writer_handle = tokio::task::spawn_blocking(move || {
                while running_writer.load(Ordering::SeqCst) {
                    match outbound_rx.blocking_recv() {
                        Some(pkt) => {
                            dev_writer.send_packet(&pkt);
                        }
                        None => break,
                    }
                }
            });

            // Task 2: Inbound reader (TUN device -> Inbound Channel)
            let dev_reader = device.clone();
            let running_reader = running.clone();
            let inbound_tx_clone = inbound_tx.clone();

            let reader_handle = tokio::task::spawn_blocking(move || {
                while running_reader.load(Ordering::SeqCst) {
                    match dev_reader.receive_blocking() {
                        Ok(bytes) => {
                            if inbound_tx_clone.blocking_send(bytes).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            if running_reader.load(Ordering::SeqCst) {
                                tracing::warn!("TUN receive error: {}", e);
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

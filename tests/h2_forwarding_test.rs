use bytes::Bytes;
use ifoxy_windows::tunnel::stream::TunneledStream;
use http::Response;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// A local mock H2 CONNECT server implementing RFC 7540 / 8484
async fn start_mock_h2_connect_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut srv_builder = h2::server::Builder::new();
                srv_builder.max_concurrent_streams(2000);
                srv_builder.initial_window_size(4 * 1024 * 1024);
                srv_builder.initial_connection_window_size(8 * 1024 * 1024);
                let mut h2_conn = match srv_builder.handshake(socket).await {
                    Ok(conn) => conn,
                    Err(_) => return,
                };

                while let Some(result) = h2_conn.accept().await {
                    let (req, mut respond) = match result {
                        Ok(parts) => parts,
                        Err(_) => break,
                    };

                    if req.method() == http::Method::CONNECT {
                        let resp = Response::builder().status(200).body(()).unwrap();
                        let mut send_stream = match respond.send_response(resp, false) {
                            Ok(stream) => stream,
                            Err(_) => break,
                        };

                        let mut recv_stream = req.into_body();

                        // Echo incoming stream payload back to client
                        tokio::spawn(async move {
                            while let Some(chunk_res) = recv_stream.data().await {
                                let chunk = match chunk_res {
                                    Ok(c) => c,
                                    Err(_) => break,
                                };
                                let len = chunk.len();
                                let _ = recv_stream.flow_control().release_capacity(len);

                                send_stream.reserve_capacity(len);
                                let is_end = recv_stream.is_end_stream();
                                if send_stream.send_data(chunk, is_end).is_err() {
                                    return;
                                }
                                if is_end {
                                    return;
                                }
                            }
                            let _ = send_stream.send_data(Bytes::new(), true);
                        });
                    }
                }
            });
        }
    });

    (addr, handle)
}

#[tokio::test]
async fn test_h2_large_transfer_100_mib() {
    // Test a single stream transferring 100 MiB across the H2 CONNECT bridge
    let (server_addr, _server_task) = start_mock_h2_connect_server().await;

    let dummy_tcp = TcpStream::connect(server_addr).await.unwrap();
    // Create H2 client connection directly with tuned windows
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(4 * 1024 * 1024);
    builder.initial_connection_window_size(8 * 1024 * 1024);
    builder.max_frame_size(16384);

    let (client, connection) = builder.handshake(dummy_tcp).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut ready_client = client.ready().await.unwrap();
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("target.example:443")
        .header("proxy-authorization", "Bearer test_token")
        .body(())
        .unwrap();

    let (response_fut, send_stream) = ready_client.send_request(req, false).unwrap();
    let response = response_fut.await.unwrap();
    assert_eq!(response.status(), 200);

    let recv_stream = response.into_body();
    let mut tunneled = TunneledStream::new(recv_stream, send_stream);

    // Stream 100 MiB in 1 MiB chunks
    const TOTAL_BYTES: usize = 100 * 1024 * 1024;
    const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

    let writer_task = tokio::spawn(async move {
        let chunk = vec![0xABu8; CHUNK_SIZE];
        let mut sent = 0;
        while sent < TOTAL_BYTES {
            tunneled.write_all(&chunk).await.unwrap();
            sent += CHUNK_SIZE;
        }
        tunneled.shutdown().await.unwrap();
        tunneled
    });

    let mut tunneled = writer_task.await.unwrap();

    let mut received = 0;
    let mut read_buf = vec![0u8; 64 * 1024];
    while received < TOTAL_BYTES {
        let n = tunneled.read(&mut read_buf).await.unwrap();
        if n == 0 {
            break;
        }
        assert_eq!(read_buf[0], 0xAB);
        received += n;
    }

    assert_eq!(
        received, TOTAL_BYTES,
        "Must transfer full 100 MiB end-to-end"
    );
}

#[tokio::test]
async fn test_h2_1000_short_flows() {
    let (server_addr, _server_task) = start_mock_h2_connect_server().await;

    let dummy_tcp = TcpStream::connect(server_addr).await.unwrap();
    let builder = h2::client::Builder::new();
    let (client, connection) = builder.handshake(dummy_tcp).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    const FLOW_COUNT: usize = 1000;
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(50));
    let mut handles = Vec::with_capacity(FLOW_COUNT);

    for i in 0..FLOW_COUNT {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let mut ready_client = client.clone().ready().await.unwrap();
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("short-flow-{}.test:80", i))
            .header("proxy-authorization", "Bearer test_token")
            .body(())
            .unwrap();

        let (resp_fut, mut send_stream) = ready_client.send_request(req, false).unwrap();
        let handle = tokio::spawn(async move {
            let _permit = permit;
            let resp = resp_fut.await.unwrap();
            assert_eq!(resp.status(), 200);
            let mut recv_stream = resp.into_body();

            let payload = format!("ping-flow-{}", i);
            send_stream
                .send_data(Bytes::from(payload.clone()), true)
                .unwrap();

            let mut out = Vec::new();
            while let Some(chunk_res) = recv_stream.data().await {
                let chunk = chunk_res.unwrap();
                let len = chunk.len();
                let _ = recv_stream.flow_control().release_capacity(len);
                out.extend_from_slice(&chunk);
            }
            assert_eq!(String::from_utf8(out).unwrap(), payload);
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }
}

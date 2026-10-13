use ifoxy_windows::vpn::netstack::DnsCache;
use std::time::Duration;

#[test]
fn test_dns_cache_stores_and_retrieves_with_matching_txid() {
    let mut cache = DnsCache::new(Duration::from_secs(60));

    // Sample raw DNS query (query for example.com, TxID = 0x1234)
    let query_txid_1 = vec![
        0x12, 0x34, // TxID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, 0x00, 0x00, // Answers, Authority, Additional
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
        0x00, // example.com
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
    ];

    // Sample raw DNS response (TxID = 0x1234)
    let response = vec![
        0x12, 0x34, // TxID
        0x81, 0x80, // Flags: response, no error
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
        0x0c, // Pointer to name
        0x00, 0x01, 0x00, 0x01, // Type A, Class IN
        0x00, 0x00, 0x00, 0x3c, // TTL 60s
        0x00, 0x04, // Data len 4
        93, 184, 216, 34, // 93.184.216.34
    ];

    // Initially cache is empty
    assert!(cache.lookup(&query_txid_1).is_none());

    // Insert response into cache
    cache.insert(&query_txid_1, response.clone());

    // Lookup with identical query (TxID = 0x1234)
    let cached = cache.lookup(&query_txid_1).expect("Cache hit");
    assert_eq!(cached, response);

    // Lookup with SAME question but DIFFERENT transaction ID (TxID = 0xABCD)
    let mut query_txid_2 = query_txid_1.clone();
    query_txid_2[0] = 0xAB;
    query_txid_2[1] = 0xCD;

    let cached_remapped = cache
        .lookup(&query_txid_2)
        .expect("Cache hit with new TxID");
    assert_eq!(
        cached_remapped[0..2],
        [0xAB, 0xCD],
        "Cached response must be remapped to client query's transaction ID"
    );
    assert_eq!(
        cached_remapped[2..],
        response[2..],
        "Response payload after TxID must match"
    );
}

#[test]
fn test_dns_cache_expiration() {
    let mut cache = DnsCache::new(Duration::from_millis(50));

    let query = vec![
        0x55, 0xAA, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, b't', b'e',
        b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    let response = vec![
        0x55, 0xAA, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, b't', b'e',
        b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x04, 1, 1, 1, 1,
    ];

    cache.insert(&query, response);
    assert!(cache.lookup(&query).is_some());

    std::thread::sleep(Duration::from_millis(70));
    assert!(
        cache.lookup(&query).is_none(),
        "Expired DNS cache entry must not be returned"
    );
}

#[test]
fn doh_response_with_content_length_is_decoded() {
    use ifoxy_windows::vpn::netstack::decode_doh_http_response;
    let body = [0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01];
    let mut resp =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 6\r\n\r\n"
            .to_vec();
    resp.extend_from_slice(&body);
    resp.extend_from_slice(b"EXTRA-IGNORED");
    assert_eq!(decode_doh_http_response(&resp).unwrap(), body.to_vec());
}

#[test]
fn doh_response_with_chunked_encoding_is_decoded_without_framing() {
    use ifoxy_windows::vpn::netstack::decode_doh_http_response;
    // Chunk sizes 3 and 4, then the terminating zero chunk. The old code
    // returned the raw chunk framing as part of the DNS message.
    let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n\x01\x02\x03\r\n4\r\n\x04\x05\x06\x07\r\n0\r\n\r\n";
    assert_eq!(
        decode_doh_http_response(resp).unwrap(),
        vec![1, 2, 3, 4, 5, 6, 7]
    );
}

#[test]
fn doh_response_errors_are_reported() {
    use ifoxy_windows::vpn::netstack::decode_doh_http_response;
    assert!(decode_doh_http_response(b"HTTP/1.1 503 Service Unavailable\r\n\r\n").is_err());
    assert!(decode_doh_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc").is_err());
    assert!(decode_doh_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").is_err());
    assert!(decode_doh_http_response(b"no headers here").is_err());
    // Absurd chunk size must be rejected, not overflow or allocate.
    assert!(decode_doh_http_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\nabc"
    )
    .is_err());
}

/// DESTRUCTIVE: changes the DNS servers of your real, active network adapter.
///
/// The previous version of this test ran by default and restored only the
/// first original server, so on a DHCP machine it left the adapter pinned to
/// 1.1.1.1 permanently. It is now `#[ignore]`d, refuses to run unless
/// `IFOXY_DESTRUCTIVE_TESTS=1` is set, and restores the complete original
/// state (including "automatic"). Run it explicitly with:
///   $env:IFOXY_DESTRUCTIVE_TESTS=1; cargo test --test dns_tunnel_test -- --ignored
/// If anything goes wrong, reset with:
///   Set-DnsClientServerAddress -InterfaceIndex <n> -ResetServerAddresses
#[cfg(windows)]
#[test]
#[ignore = "modifies the DNS settings of the real active adapter"]
fn test_real_windows_interface_dns_settings_readback() {
    use ifoxy_windows::vpn::iphlpapi::{
        native_get_best_route, native_get_interface_dns, native_set_interface_dns,
        native_set_interface_dns_servers,
    };
    use std::net::Ipv4Addr;

    if std::env::var("IFOXY_DESTRUCTIVE_TESTS").as_deref() != Ok("1") {
        panic!("Set IFOXY_DESTRUCTIVE_TESTS=1 to run this test; it changes real adapter DNS.");
    }

    let (_, if_index) = native_get_best_route(Ipv4Addr::new(8, 8, 8, 8)).expect("Get best route");
    // "Automatic" can come back as None or as an empty string.
    let norm = |o: Option<String>| o.filter(|s| !s.is_empty());
    let original = norm(native_get_interface_dns(if_index).expect("Get current interface DNS"));

    let set_res = native_set_interface_dns(if_index, Ipv4Addr::new(1, 1, 1, 1));
    let read_back = native_get_interface_dns(if_index);

    // Always restore the COMPLETE original state before asserting anything.
    let restore = native_set_interface_dns_servers(if_index, original.as_deref());

    assert_eq!(set_res, Ok(()), "SetInterfaceDnsSettings must succeed");
    assert_eq!(
        read_back.expect("read back").as_deref(),
        Some("1.1.1.1"),
        "Configured DNS server must match read-back value"
    );
    assert_eq!(restore, Ok(()), "Restoring the original DNS must succeed");
    assert_eq!(
        norm(native_get_interface_dns(if_index).expect("read after restore")),
        original,
        "Original DNS configuration must be fully restored"
    );
}

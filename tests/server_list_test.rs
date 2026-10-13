use ifoxy_windows::servers::client::ServerListClient;
use ifoxy_windows::servers::model::{VpnCity, VpnCountry, VpnProtocol, VpnServerNode};
use ifoxy_windows::servers::ping::measure_tcp_latency;
use std::time::Duration;
use tokio::net::TcpListener;

#[test]
fn test_parse_country_record() {
    let sample = r#"{
        "name": "Germany",
        "code": "DE",
        "cities": [
            {
                "name": "Frankfurt",
                "code": "FRA",
                "servers": [
                    {
                        "hostname": "fra-vpn.mozilla.org",
                        "port": 443,
                        "quarantined": false,
                        "protocols": [{"name": "connect", "host": "fra-edge.fastly.net", "port": 443}]
                    }
                ]
            }
        ]
    }"#;
    let country: VpnCountry = serde_json::from_str(sample).expect("parse failed");
    assert_eq!(country.code, "DE");
    assert_eq!(country.name, "Germany");
    assert_eq!(country.cities.len(), 1);
    assert_eq!(country.cities[0].name, "Frankfurt");
    assert_eq!(country.cities[0].servers[0].hostname, "fra-vpn.mozilla.org");
    assert!(!country.cities[0].servers[0].quarantined);
}

#[test]
fn test_candidates_extraction_and_filtering() {
    let sample_country = VpnCountry {
        name: "United States".to_string(),
        code: "US".to_string(),
        cities: vec![VpnCity {
            name: "New York".to_string(),
            code: "NYC".to_string(),
            servers: vec![
                VpnServerNode {
                    hostname: "nyc-1.vpn.mozilla.org".to_string(),
                    port: 443,
                    quarantined: false,
                    protocols: vec![VpnProtocol {
                        name: "connect".to_string(),
                        host: "nyc-edge.fastly.net".to_string(),
                        port: 443,
                        scheme: None,
                        template_string: None,
                    }],
                },
                VpnServerNode {
                    hostname: "nyc-bad.vpn.mozilla.org".to_string(),
                    port: 443,
                    quarantined: true, // Should be ignored
                    protocols: vec![VpnProtocol {
                        name: "connect".to_string(),
                        host: "nyc-bad-edge.fastly.net".to_string(),
                        port: 443,
                        scheme: None,
                        template_string: None,
                    }],
                },
            ],
        }],
    };

    let countries = vec![sample_country];
    let candidates = ServerListClient::candidates_for_country(&countries, "US");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].host, "nyc-edge.fastly.net");
    assert_eq!(candidates[0].port, 443);
    assert_eq!(candidates[0].city_code, "NYC");
}

#[tokio::test]
async fn test_measure_tcp_latency_local() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let port = listener.local_addr().expect("local_addr failed").port();

    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let latency = measure_tcp_latency("127.0.0.1", port, Duration::from_millis(500))
        .await
        .expect("latency measurement failed");

    // Local loopback latency is usually very small (< 100ms)
    assert!(latency < 500);
}

#[tokio::test]
async fn test_probe_and_rank_candidates_and_failover() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let active_port = listener.local_addr().expect("local_addr").port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });

    let mut candidates = vec![
        ifoxy_windows::servers::model::ProxyCandidate {
            host: "127.0.0.1".to_string(),
            port: 1, // Closed port
            country_code: "US".to_string(),
            country_name: "United States".to_string(),
            city_code: "NYC".to_string(),
            city_name: None,
            latency_ms: None,
        },
        ifoxy_windows::servers::model::ProxyCandidate {
            host: "127.0.0.1".to_string(),
            port: active_port, // Open port (will respond quickly)
            country_code: "DE".to_string(),
            country_name: "Germany".to_string(),
            city_code: "FRA".to_string(),
            city_name: None,
            latency_ms: None,
        },
    ];

    ServerListClient::probe_and_rank_candidates(&mut candidates, Duration::from_millis(200)).await;

    // Active candidate should be ranked first because it succeeded
    assert_eq!(candidates[0].port, active_port);
    assert!(candidates[0].latency_ms.is_some());

    // Inactive candidate should be ranked second
    assert_eq!(candidates[1].port, 1);

    // Failover candidate list preserves ranking
    let failover = ServerListClient::select_failover_candidates(candidates);
    assert_eq!(failover.len(), 2);
    assert_eq!(failover[0].port, active_port);
    assert_eq!(failover[1].port, 1);
}

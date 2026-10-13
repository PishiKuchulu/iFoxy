use super::model::{ProxyCandidate, VpnCountry, VpnServerNode};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use reqwest::Client;
use serde_json::Value;
use thiserror::Error;

pub const REMOTE_SETTINGS_URL: &str =
    "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records";
pub const RECOMMENDED_COUNTRY_CODE: &str = "REC";
const EXCLUDED_COUNTRY_NAMES: &[&str] = &["CatchAll Anycast"];
const MOZILLA_VPN_USER_AGENT: &str = "MozillaVPN/2.35.0 (sys:linux; iap:true)";

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Parse error: {0}")]
    Parse(String),
}

pub struct ServerListClient {
    client: Client,
}

impl ServerListClient {
    pub fn new() -> Self {
        Self {
            client: crate::http_client::create_default_client().unwrap_or_else(|e| {
                tracing::warn!("Failed to build default HTTP client: {:?}", e);
                Client::new()
            }),
        }
    }

    pub fn with_client(client: Client) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn fetch_countries(&self) -> Result<Vec<VpnCountry>, ServerError> {
        self.fetch_countries_from(REMOTE_SETTINGS_URL).await
    }

    pub async fn fetch_countries_from(&self, url: &str) -> Result<Vec<VpnCountry>, ServerError> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(MOZILLA_VPN_USER_AGENT));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let res = self.client.get(url).headers(headers).send().await?;

        if !res.status().is_success() {
            return Err(ServerError::Parse(format!(
                "Remote settings status error: {}",
                res.status()
            )));
        }

        let body: Value = res.json().await?;
        let empty_vec = Vec::new();
        let records = body["data"].as_array().unwrap_or(&empty_vec);

        let mut countries = Vec::new();
        for record in records {
            let country_val = if record.get("country").is_some() {
                &record["country"]
            } else {
                record
            };

            if let Ok(country) = serde_json::from_value::<VpnCountry>(country_val.clone()) {
                let is_excluded = EXCLUDED_COUNTRY_NAMES
                    .iter()
                    .any(|&ex| ex.eq_ignore_ascii_case(&country.name));
                if !country.code.trim().is_empty() && !country.cities.is_empty() && !is_excluded {
                    countries.push(country);
                }
            }
        }

        Ok(countries)
    }

    pub fn default_connect_target(server: &VpnServerNode) -> Option<(String, u16)> {
        for proto in &server.protocols {
            if proto.name == "connect" {
                let host = if !proto.host.trim().is_empty() {
                    proto.host.clone()
                } else {
                    server.hostname.clone()
                };
                let port = if proto.port != 0 {
                    proto.port
                } else {
                    server.port
                };
                return Some((host, port));
            }
        }

        if server.protocols.is_empty() && !server.hostname.trim().is_empty() && server.port != 0 {
            Some((server.hostname.clone(), server.port))
        } else {
            None
        }
    }

    pub fn candidates_for_country(
        countries: &[VpnCountry],
        country_code: &str,
    ) -> Vec<ProxyCandidate> {
        let mut candidates = Vec::new();
        for country in countries {
            if !country.code.eq_ignore_ascii_case(country_code) {
                continue;
            }
            for city in &country.cities {
                for server in &city.servers {
                    if server.quarantined {
                        continue;
                    }
                    if let Some((host, port)) = Self::default_connect_target(server) {
                        candidates.push(ProxyCandidate {
                            host,
                            port,
                            country_code: country.code.clone(),
                            country_name: country.name.clone(),
                            city_code: city.code.clone(),
                            city_name: Some(city.name.clone()),
                            latency_ms: None,
                        });
                    }
                }
            }
        }
        candidates
    }

    pub fn candidates_for_city(
        countries: &[VpnCountry],
        country_code: &str,
        city_code: &str,
    ) -> Vec<ProxyCandidate> {
        Self::candidates_for_country(countries, country_code)
            .into_iter()
            .filter(|c| c.city_code.eq_ignore_ascii_case(city_code))
            .collect()
    }

    /// Concurrently probe candidates for TCP latency and rank by lowest RTT (M3)
    pub async fn probe_and_rank_candidates(
        candidates: &mut [ProxyCandidate],
        timeout: std::time::Duration,
    ) {
        let mut join_set = tokio::task::JoinSet::new();
        for (idx, c) in candidates.iter().enumerate() {
            let host = c.host.clone();
            let port = c.port;
            join_set.spawn(async move {
                let res = crate::servers::ping::measure_tcp_latency(&host, port, timeout)
                    .await
                    .ok();
                (idx, res)
            });
        }

        while let Some(res) = join_set.join_next().await {
            if let Ok((idx, latency)) = res {
                candidates[idx].latency_ms = latency;
            }
        }

        candidates.sort_by(|a, b| match (a.latency_ms, b.latency_ms) {
            (Some(la), Some(lb)) => la.cmp(&lb),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
    }

    /// Select optimal candidates with ordered failover fallbacks (M3)
    pub fn select_failover_candidates(mut candidates: Vec<ProxyCandidate>) -> Vec<ProxyCandidate> {
        candidates.sort_by(|a, b| match (a.latency_ms, b.latency_ms) {
            (Some(la), Some(lb)) => la.cmp(&lb),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        candidates
    }
}

impl Default for ServerListClient {
    fn default() -> Self {
        Self::new()
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnProtocol {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default, rename = "templateString")]
    pub template_string: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnServerNode {
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub quarantined: bool,
    #[serde(default)]
    pub protocols: Vec<VpnProtocol>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnCity {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub servers: Vec<VpnServerNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnCountry {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub cities: Vec<VpnCity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyCandidate {
    pub host: String,
    pub port: u16,
    pub country_code: String,
    pub country_name: String,
    pub city_code: String,
    #[serde(default)]
    pub city_name: Option<String>,
    #[serde(default)]
    pub latency_ms: Option<u64>,
}

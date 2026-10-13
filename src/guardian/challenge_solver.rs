use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, ORIGIN, USER_AGENT};
use reqwest::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SOLVER_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
const POW_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Error, Debug)]
pub enum ChallengeError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Challenge format error: {0}")]
    Format(String),
    #[error("Proof of work solver failed")]
    PowFailed,
}

pub struct FastlyChallengeSolver {
    client: Client,
}

impl FastlyChallengeSolver {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .cookie_store(true)
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn with_client(client: Client) -> Self {
        Self { client }
    }

    pub fn solve_pow(base: &str, target_hex: &str) -> Option<String> {
        let target = hex::decode(target_hex).ok()?;
        if target.len() != 32 {
            return None;
        }

        let alphabet: Vec<char> = POW_ALPHABET.chars().collect();
        for &a in &alphabet {
            for &b in &alphabet {
                let suffix = format!("{}{}", a, b);
                let candidate = format!("{}{}", base, suffix);
                let mut hasher = Sha256::new();
                hasher.update(candidate.as_bytes());
                if hasher.finalize().as_slice() == target.as_slice() {
                    return Some(suffix);
                }
            }
        }
        None
    }

    fn client_metrics_answer() -> Value {
        json!({
            "ty": "clientmetrics",
            "webdriver": false,
            "bot_detection_result": {
                "bot_detected": false,
                "bot_kind": null
            },
            "browser_metrics": {
                "client_data": "{}",
                "error_trace": null
            },
            "detector_results": {},
            "v": 2
        })
    }

    pub async fn solve_and_install(&self, base_host: &str) -> Result<(), ChallengeError> {
        let page_url = format!("{}/", base_host.trim_end_matches('/'));
        let res = self
            .client
            .get(&page_url)
            .header(USER_AGENT, SOLVER_USER_AGENT)
            .send()
            .await?;
        let body = res.text().await.unwrap_or_default();

        if !body.contains("/_fs-ch-") || !body.contains("Client Challenge") {
            return Ok(());
        }

        let re_prefix = regex::Regex::new(r"/_fs-ch-[A-Za-z0-9]+").unwrap();
        let prefix = re_prefix.find(&body).map(|m| m.as_str()).ok_or_else(|| {
            ChallengeError::Format("Challenge asset prefix not found".to_string())
        })?;
        let prefix_url = format!("{}{}", base_host.trim_end_matches('/'), prefix);

        let script_url = format!("{}/script.js?reload=true", prefix_url);
        let script = self
            .client
            .get(&script_url)
            .header(USER_AGENT, SOLVER_USER_AGENT)
            .send()
            .await?
            .text()
            .await
            .unwrap_or_default();

        let re_init = regex::Regex::new(r#"init\((\[[^\]]*\]),\s*"([^"]+)",\s*"([^"]+)""#).unwrap();
        let captures = re_init.captures(&script).ok_or_else(|| {
            ChallengeError::Format("init() not found in challenge script".to_string())
        })?;

        let challenges_json: Value = serde_json::from_str(&captures[1])
            .map_err(|e| ChallengeError::Format(e.to_string()))?;
        let token = captures[2].to_string();

        let mut answers = Vec::new();
        if let Some(challenges) = challenges_json.as_array() {
            for ch in challenges {
                let ty = ch["ty"].as_str().unwrap_or_default();
                let data = &ch["data"];
                match ty {
                    "pow" => {
                        let base = data["base"].as_str().unwrap_or_default();
                        let hash = data["hash"].as_str().unwrap_or_default();
                        let answer =
                            Self::solve_pow(base, hash).ok_or(ChallengeError::PowFailed)?;
                        answers.push(json!({
                            "ty": "pow",
                            "base": base,
                            "answer": answer,
                            "hmac": data["hmac"],
                            "expires": data["expires"]
                        }));
                    }
                    "clientmetrics" => {
                        answers.push(Self::client_metrics_answer());
                    }
                    _ => {}
                }
            }
        }

        let post_back_url = format!("{}/fst-post-back", prefix_url);
        let post_body = json!({
            "token": token,
            "data": answers
        });

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(SOLVER_USER_AGENT));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            ORIGIN,
            HeaderValue::from_str(base_host).map_err(|e| ChallengeError::Format(e.to_string()))?,
        );

        let post_res = self
            .client
            .post(&post_back_url)
            .headers(headers)
            .json(&post_body)
            .send()
            .await?;

        if !post_res.status().is_success() {
            return Err(ChallengeError::Format(format!(
                "Post-back failed with status {}",
                post_res.status()
            )));
        }

        Ok(())
    }
}

impl Default for FastlyChallengeSolver {
    fn default() -> Self {
        Self::new()
    }
}

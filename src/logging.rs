use regex::Regex;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const DEFAULT_MAX_LOG_SIZE: u64 = 5 * 1024 * 1024; // 5 MiB
pub const DEFAULT_MAX_LOG_FILES: usize = 3;

/// Redact sensitive secrets (tokens, passwords, Hawk macs) from logs (M1)
pub fn redact_sensitive_text(text: &str) -> String {
    lazy_static_regex(text)
}

fn lazy_static_regex(text: &str) -> String {
    // 1. Redact Bearer tokens
    let re_bearer = Regex::new(r"(?i)bearer\s+[A-Za-z0-9\-_.]+").unwrap();
    let text = re_bearer.replace_all(text, "Bearer [REDACTED]");

    // 2. Redact JSON tokens and passwords
    let re_token_json = Regex::new(r#"(?i)("(?:token|access_token|sessionToken|authPW|password|secret|hmac_key)"\s*:\s*")[^"]+(")"#).unwrap();
    let text = re_token_json.replace_all(&text, "${1}[REDACTED]${2}");

    // 3. Redact Hawk header components
    let re_hawk_id = Regex::new(r#"(?i)Hawk\s+id="[^"]+""#).unwrap();
    let text = re_hawk_id.replace_all(&text, "Hawk id=\"[REDACTED]\"");

    let re_hawk_mac = Regex::new(r#"(?i)mac="[^"]+""#).unwrap();
    let text = re_hawk_mac.replace_all(&text, "mac=\"[REDACTED]\"");

    // 4. Redact X-iFoxy-Token header values
    let re_foxy_tok = Regex::new(r"(?i)x-ifoxy-token:\s*[A-Za-z0-9\-_.]+").unwrap();
    let text = re_foxy_tok.replace_all(&text, "x-ifoxy-token: [REDACTED]");

    text.to_string()
}

/// Thread-safe size-based rolling file writer with sensitive data redaction (M1)
pub struct RollingFileWriter {
    base_path: PathBuf,
    max_size_bytes: u64,
    max_files: usize,
    current_file: Option<File>,
    current_size: u64,
}

impl RollingFileWriter {
    pub fn new(base_path: PathBuf, max_size_bytes: u64, max_files: usize) -> io::Result<Self> {
        if let Some(parent) = base_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let (current_file, current_size) = Self::open_or_create(&base_path)?;
        Ok(Self {
            base_path,
            max_size_bytes,
            max_files,
            current_file: Some(current_file),
            current_size,
        })
    }

    fn open_or_create(path: &Path) -> io::Result<(File, u64)> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata()?.len();
        Ok((file, size))
    }

    fn rotate_if_needed(&mut self, additional_bytes: u64) -> io::Result<()> {
        if self.current_size + additional_bytes > self.max_size_bytes && self.current_size > 0 {
            // Close current file
            self.current_file = None;

            // Shift older log files: ifoxy.log.2 -> ifoxy.log.3, etc.
            for i in (1..self.max_files).rev() {
                let from = self.base_path.with_extension(format!("log.{}", i));
                let to = self.base_path.with_extension(format!("log.{}", i + 1));
                if from.exists() {
                    let _ = fs::rename(&from, &to);
                }
            }

            // Rename current to ifoxy.log.1
            let first_backup = self.base_path.with_extension("log.1");
            let _ = fs::rename(&self.base_path, &first_backup);

            // Recreate new empty base file
            let (new_file, new_size) = Self::open_or_create(&self.base_path)?;
            self.current_file = Some(new_file);
            self.current_size = new_size;
        }
        Ok(())
    }

    pub fn write_log_line(&mut self, line: &str) -> io::Result<()> {
        let redacted = redact_sensitive_text(line);
        let bytes = redacted.as_bytes();
        let total_bytes = bytes.len() as u64 + 1; // + newline

        self.rotate_if_needed(total_bytes)?;

        if let Some(ref mut file) = self.current_file {
            file.write_all(bytes)?;
            file.write_all(b"\n")?;
            file.flush()?;
            self.current_size += total_bytes;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct SharedRollingLogger(pub Arc<Mutex<RollingFileWriter>>);

impl io::Write for SharedRollingLogger {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let mut writer = self.0.lock().unwrap();
        writer.write_log_line(&text)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn default_log_path() -> PathBuf {
    crate::paths::state_dir().join("logs").join("ifoxy.log")
}

pub fn init_rolling_logger() -> Option<tracing::subscriber::DefaultGuard> {
    let log_path = default_log_path();
    if let Ok(writer) =
        RollingFileWriter::new(log_path, DEFAULT_MAX_LOG_SIZE, DEFAULT_MAX_LOG_FILES)
    {
        let shared = SharedRollingLogger(Arc::new(Mutex::new(writer)));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || shared.clone())
            .with_ansi(false)
            .finish();
        Some(tracing::subscriber::set_default(subscriber))
    } else {
        None
    }
}

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EbpfEvent {
    #[serde(default = "default_schema_version")]
    pub schema_version: u16,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub event_type: String,
    #[serde(default)]
    pub pid: Option<i64>,
    #[serde(default)]
    pub ppid: Option<i64>,
    #[serde(default)]
    pub uid: Option<i64>,
    #[serde(default)]
    pub gid: Option<i64>,
    #[serde(default)]
    pub comm: Option<String>,
    #[serde(default)]
    pub binary: Option<String>,
    #[serde(default)]
    pub arguments_sample: Vec<String>,
    #[serde(default)]
    pub argv_truncated: bool,
    #[serde(default)]
    pub cgroup_id: Option<String>,
    #[serde(default)]
    pub container_id: Option<String>,
    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dest_ip: Option<String>,
    #[serde(default)]
    pub dest_port: Option<u16>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub access_type: Option<String>,
    #[serde(default)]
    pub severity_hint: Option<String>,
    #[serde(default)]
    pub raw: serde_json::Value,
}

impl EbpfEvent {
    pub fn normalized(mut self, host: Option<&str>) -> Self {
        if self.schema_version == 0 {
            self.schema_version = SCHEMA_VERSION;
        }
        if self.host.is_none() {
            self.host = host.map(str::to_string);
        }
        self.arguments_sample = redact_args(&self.arguments_sample);
        self
    }

    pub fn is_high_signal(&self) -> bool {
        matches!(
            self.event_type.as_str(),
            "privilege_change" | "file_access" | "process_exec" | "network_connect"
        ) && matches!(
            self.severity_hint.as_deref(),
            Some("medium" | "high" | "critical")
        )
    }
}

pub fn event_to_ndjson(event: &EbpfEvent) -> Result<String, serde_json::Error> {
    serde_json::to_string(event).map(|line| format!("{line}\n"))
}

/// Serialize an event directly into a writer as a single NDJSON line,
/// avoiding intermediate `String` allocation. The caller is responsible
/// for flushing.
pub fn event_write_ndjson<W: std::io::Write>(
    event: &EbpfEvent,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    serde_json::to_writer(&mut *writer, event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    writer.write_all(b"\n")
}

pub fn event_from_json_line(line: &str) -> Result<Option<EbpfEvent>, serde_json::Error> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    serde_json::from_str(trimmed).map(Some)
}

pub fn redact_args(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| {
            let lower = value.to_ascii_lowercase();
            if lower.contains("password")
                || lower.contains("passwd")
                || lower.contains("token")
                || lower.contains("secret")
                || lower.contains("api_key")
                || lower.contains("apikey")
                || lower.contains("private_key")
            {
                "[redacted]".to_string()
            } else {
                value.clone()
            }
        })
        .collect()
}

fn default_schema_version() -> u16 {
    SCHEMA_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sensitive_arguments() {
        let args = vec![
            "curl".to_string(),
            "--token=abc".to_string(),
            "safe".to_string(),
        ];

        assert_eq!(
            redact_args(&args),
            vec![
                "curl".to_string(),
                "[redacted]".to_string(),
                "safe".to_string()
            ]
        );
    }

    #[test]
    fn parses_json_line() {
        let event = event_from_json_line(
            r#"{"schema_version":1,"timestamp":"2026-06-16T00:00:00Z","event_type":"process_exec","arguments_sample":["sh"]}"#,
        )
        .unwrap()
        .unwrap();

        assert_eq!(event.event_type, "process_exec");
        assert_eq!(event.arguments_sample, vec!["sh"]);
    }
}

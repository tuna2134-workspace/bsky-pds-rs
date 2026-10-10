//! Outbound email: confirmation + password-reset delivery.
//!
//! `PDS_EMAIL_SMTP_URL` forms (else log-only dev mode):
//! - `smtps://user:pass@host:465/` — implicit TLS
//! - `smtp://user:pass@host:587/` — STARTTLS when advertised, else plain
//! - `smtp:///?sendmail=true` — unsupported here (no local sendmail on
//!   Workers); falls back to log mode with a warning outcome.
//!
//! Log mode returns `Logged` (token also in platform logs) so local
//! development works without an SMTP server.

use crate::pds_env;
use crate::xrpc::{XrpcError, XrpcResult};
use worker::Env;

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub implicit_tls: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SendOutcome {
    Sent,
    /// No SMTP configured: token logged, caller must surface it out-of-band.
    Logged(String),
}

pub fn smtp_config_from_url(url: &str) -> Result<Option<SmtpConfig>, String> {
    let url = url.trim();
    if url.is_empty() {
        return Ok(None);
    }
    if url.contains("sendmail=true") {
        return Ok(None); // no local sendmail on Workers; log mode
    }
    let (scheme, rest) = url.split_once("://").ok_or("bad SMTP URL")?;
    let implicit_tls = match scheme {
        "smtps" => true,
        "smtp" => false,
        _ => return Err("SMTP scheme must be smtp:// or smtps://".into()),
    };
    let (auth_host, _path) = match rest.split_once('/') {
        Some((a, p)) => (a, p),
        None => (rest, ""),
    };
    // userinfo@host:port — userinfo may be percent-encoded.
    let (userinfo, hostport) = auth_host.rsplit_once('@').ok_or("SMTP userinfo required")?;
    let (user_enc, pass_enc) = userinfo.split_once(':').ok_or("SMTP password required")?;
    let username = pct_decode(user_enc)?;
    let password = pct_decode(pass_enc)?;
    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| "bad SMTP port")?),
        None => (hostport.to_string(), if implicit_tls { 465 } else { 587 }),
    };
    if host.is_empty() {
        return Err("SMTP host required".into());
    }
    Ok(Some(SmtpConfig { host, port, username, password, implicit_tls }))
}

fn pct_decode(s: &str) -> Result<String, String> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return Err("bad percent encoding".into());
            }
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).map_err(|_| "bad percent encoding")?;
            let v = u8::from_str_radix(hex, 16).map_err(|_| "bad percent encoding")?;
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "bad percent encoding".into())
}

/// Compose a minimal plaintext message (LF endings; transport converts).
pub fn compose_message(from: &str, to: &str, subject: &str, text: &str) -> String {
    // Dot-stuffing for SMTP DATA transparency.
    let body = text
        .replace("\r\n", "\n")
        .split('\n')
        .map(|line| if line.starts_with('.') { format!(".{line}") } else { line.to_string() })
        .collect::<Vec<_>>()
        .join("\r\n");
    format!("From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n")
}

// ---------- line transport ----------

#[async_trait::async_trait(?Send)]
pub trait LineTransport {
    async fn read_line(&mut self) -> Result<String, String>;
    async fn write_line(&mut self, line: &str) -> Result<(), String>;
}

/// Read an SMTP reply (handles `250-...` multiline). Returns (code, text).
pub async fn read_reply<T: LineTransport>(t: &mut T) -> Result<(u16, String), String> {
    let mut text = String::new();
    loop {
        let line = t.read_line().await?;
        if line.len() < 4 {
            return Err("short SMTP reply".into());
        }
        let code: u16 = line[..3].parse().map_err(|_| "bad SMTP code")?;
        text.push_str(line[4..].trim());
        if line.as_bytes()[3] == b' ' {
            return Ok((code, text));
        }
        text.push('\n');
        if text.len() > 16 * 1024 {
            return Err("SMTP reply too long".into());
        }
    }
}

async fn expect<T: LineTransport>(t: &mut T, want: &[u16]) -> Result<String, String> {
    let (code, text) = read_reply(t).await?;
    if want.contains(&code) {
        Ok(text)
    } else {
        Err(format!("SMTP error {code}: {text}"))
    }
}

fn b64(s: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(s)
}

/// Read greeting + EHLO. Returns capability text (uppercased by caller).
async fn phase_greeting<T: LineTransport>(t: &mut T) -> Result<String, String> {
    expect(t, &[220]).await?; // greeting
    t.write_line(&format!("EHLO {}", "pds")).await?;
    let (_, ehlo) = read_reply(t).await?;
    Ok(ehlo)
}

/// AUTH + MAIL + RCPT + DATA + QUIT. `caps_upper` comes from a prior EHLO
/// (greeting is never repeated: some servers tolerate it, scripts do not).
async fn submit_rest<T: LineTransport>(
    t: &mut T,
    cfg: &SmtpConfig,
    caps_upper: &str,
    from: &str,
    to: &str,
    data: &str,
) -> Result<(), String> {
    if caps_upper.contains("AUTH") {
        if caps_upper.contains("LOGIN") {
            t.write_line("AUTH LOGIN").await?;
            expect(t, &[334]).await?;
            t.write_line(&b64(&cfg.username)).await?;
            expect(t, &[334]).await?;
            t.write_line(&b64(&cfg.password)).await?;
            expect(t, &[235]).await?;
        } else if caps_upper.contains("PLAIN") {
            let resp = b64(&format!("\0{}\0{}", cfg.username, cfg.password));
            t.write_line(&format!("AUTH PLAIN {resp}")).await?;
            expect(t, &[235]).await?;
        } else {
            return Err("no supported SMTP auth".into());
        }
    }
    t.write_line(&format!("MAIL FROM:<{from}>")).await?;
    expect(t, &[250]).await?;
    t.write_line(&format!("RCPT TO:<{to}>")).await?;
    expect(t, &[250, 251]).await?;
    t.write_line("DATA").await?;
    expect(t, &[354]).await?;
    for line in data.split("\r\n") {
        t.write_line(line).await?;
    }
    t.write_line(".").await?;
    expect(t, &[250]).await?;
    t.write_line("QUIT").await?;
    let _ = read_reply(t).await;
    Ok(())
}

/// Test seam: full conversation; returns `UPGRADE` when STARTTLS is required.
async fn smtp_conversation<T: LineTransport>(
    t: &mut T,
    cfg: &SmtpConfig,
    from: &str,
    to: &str,
    data: &str,
) -> Result<(), String> {
    let caps = phase_greeting(t).await?.to_uppercase();
    if !cfg.implicit_tls && caps.contains("STARTTLS") {
        return Err("STARTTLS-UPGRADE".into());
    }
    submit_rest(t, cfg, &caps, from, to, data).await
}

// ---------- socket transport ----------

pub struct SocketTransport {
    reader: tokio::io::BufReader<tokio::io::ReadHalf<worker::Socket>>,
    writer: tokio::io::WriteHalf<worker::Socket>,
    buf: Vec<u8>,
}

impl SocketTransport {
    pub fn new(socket: worker::Socket) -> Self {
        let (reader, writer) = tokio::io::split(socket);
        Self { reader: tokio::io::BufReader::new(reader), writer, buf: Vec::new() }
    }

    /// Recover the socket (drops buffered reader state; call only at a
    /// protocol boundary — right after requesting STARTTLS).
    pub fn into_socket(self) -> worker::Socket {
        self.reader.into_inner().unsplit(self.writer)
    }
}

#[async_trait::async_trait(?Send)]
impl LineTransport for SocketTransport {
    async fn read_line(&mut self) -> Result<String, String> {
        use tokio::io::AsyncBufReadExt;
        self.buf.clear();
        self.reader
            .read_until(b'\n', &mut self.buf)
            .await
            .map_err(|e| e.to_string())?;
        if self.buf.is_empty() {
            return Err("SMTP EOF".into());
        }
        while self.buf.ends_with(b"\n") || self.buf.ends_with(b"\r") {
            self.buf.pop();
        }
        String::from_utf8(self.buf.clone()).map_err(|_| "SMTP non-UTF8".into())
    }

    async fn write_line(&mut self, line: &str) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        self.writer
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        self.writer.flush().await.map_err(|e| e.to_string())
    }
}

/// Submit one message, upgrading to TLS when the server offers STARTTLS.
/// The whole attempt is bounded (30s) so a dead SMTP host cannot hang a request.
pub async fn smtp_send(cfg: &SmtpConfig, from: &str, to: &str, data: &str) -> Result<(), String> {
    use futures_util::future::{select, Either};
    let attempt = smtp_send_inner(cfg, from, to, data);
    let timeout = worker::Delay::from(std::time::Duration::from_secs(30));
    futures_util::pin_mut!(attempt, timeout);
    match select(attempt, timeout).await {
        Either::Left((r, _)) => r,
        Either::Right(_) => Err("SMTP timeout (30s)".into()),
    }
}

async fn smtp_send_inner(cfg: &SmtpConfig, from: &str, to: &str, data: &str) -> Result<(), String> {
    use worker::Socket;
    if cfg.implicit_tls {
        let socket = Socket::builder()
            .secure_transport(worker::SecureTransport::On)
            .connect(cfg.host.clone(), cfg.port)
            .map_err(|e| e.to_string())?;
        let mut t = SocketTransport::new(socket);
        return smtp_conversation(&mut t, cfg, from, to, data).await;
    }
    // Plain connect; probe capabilities first so we can upgrade cleanly.
    let socket = Socket::builder()
        .secure_transport(worker::SecureTransport::StartTls)
        .connect(cfg.host.clone(), cfg.port)
        .map_err(|e| e.to_string())?;
    let mut t = SocketTransport::new(socket);
    let caps = phase_greeting(&mut t)
        .await
        .map_err(|e| format!("smtp greeting failed: {e}"))?
        .to_uppercase();
    if caps.contains("STARTTLS") {
        t.write_line("STARTTLS").await?;
        expect(&mut t, &[220]).await?;
        let socket = t.into_socket().start_tls();
        let mut t2 = SocketTransport::new(socket);
        let caps2 = phase_greeting(&mut t2).await?.to_uppercase();
        return submit_rest(&mut t2, cfg, &caps2, from, to, data).await;
    }
    // No STARTTLS offered: continue in the clear (server may still allow it).
    submit_rest(&mut t, cfg, &caps, from, to, data).await
}

// ---------- high-level send ----------

/// Send a transactional email, or log the token when no SMTP is configured.
pub async fn send_email(env: &Env, to: &str, subject: &str, text: &str) -> XrpcResult<SendOutcome> {
    let cfg = pds_env::PdsEnv::from_env(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let from = cfg
        .email_from
        .clone()
        .unwrap_or_else(|| format!("no-reply@{}", cfg.hostname));
    let smtp_url = env
        .var("PDS_EMAIL_SMTP_URL")
        .map(|v| v.to_string())
        .ok()
        .filter(|s| !s.trim().is_empty())
        ;
    let data = compose_message(&from, to, subject, text);
    match smtp_url {
        None => {
            worker::console_log!("PDS email (log mode) to={to} subject={subject}\n{text}");
            Ok(SendOutcome::Logged(text.to_string()))
        }
        Some(url) => {
            let smtp = smtp_config_from_url(&url).map_err(XrpcError::internal)?;
            match smtp {
                None => {
                    worker::console_warn!("PDS_EMAIL_SMTP_URL uses sendmail transport (unsupported on Workers); logging instead");
                    worker::console_log!("PDS email (log mode) to={to} subject={subject}\n{text}");
                    Ok(SendOutcome::Logged(text.to_string()))
                }
                Some(smtp) => smtp_send(&smtp, &from, to, &data)
                    .await
                    .map(|_| SendOutcome::Sent)
                    .map_err(XrpcError::internal),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct ScriptTransport {
        script: VecDeque<ScriptStep>,
        pub written: Vec<String>,
    }

    enum ScriptStep {
        Read(String),
    }

    impl ScriptTransport {
        fn new(reads: &[&str]) -> Self {
            Self {
                script: reads.iter().map(|s| ScriptStep::Read(s.to_string())).collect(),
                written: Vec::new(),
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl LineTransport for ScriptTransport {
        async fn read_line(&mut self) -> Result<String, String> {
            match self.script.pop_front() {
                Some(ScriptStep::Read(line)) => Ok(line),
                None => Err("script exhausted".into()),
            }
        }
        async fn write_line(&mut self, line: &str) -> Result<(), String> {
            self.written.push(line.to_string());
            Ok(())
        }
    }

    fn test_cfg() -> SmtpConfig {
        SmtpConfig {
            host: "smtp.example.com".into(),
            port: 465,
            username: "user&name@oci".into(),
            password: "p@ssword".into(),
            implicit_tls: true,
        }
    }

    #[test]
    fn smtp_url_parsing() {
        let c = smtp_config_from_url("smtps://resend:re_key@smtp.resend.com:465/").unwrap().unwrap();
        assert_eq!((c.host, c.port, c.implicit_tls), ("smtp.resend.com".into(), 465, true));
        assert_eq!((c.username, c.password), ("resend".into(), "re_key".into()));
        let c = smtp_config_from_url("smtps://user%26name%40oci:p%40ssword@smtphost:465").unwrap().unwrap();
        assert_eq!(c.username, "user&name@oci");
        assert_eq!(c.password, "p@ssword");
        assert!(smtp_config_from_url("").unwrap().is_none());
        assert!(smtp_config_from_url("smtp:///?sendmail=true").unwrap().is_none());
        assert!(smtp_config_from_url("http://x/").is_err());
    }

    #[test]
    fn message_compose_dot_stuffs() {
        let m = compose_message("a@x", "b@y", "Hi", "line1\n.line2");
        assert!(m.contains("\r\n..line2"));
        assert!(m.starts_with("From: a@x\r\nTo: b@y\r\nSubject: Hi\r\n"));
    }

    #[worker::send]
    async fn run_login_flow() -> (SmtpConfig, Vec<String>) {
        let cfg = test_cfg();
        let mut t = ScriptTransport::new(&[
            "220 smtp.example.com ESMTP",
            "250-smtp.example.com",
            "250-AUTH LOGIN PLAIN",
            "250 STARTTLS",
            "334 VXNlcm5hbWU6",
            "334 UGFzc3dvcmQ6",
            "235 OK",
            "250 OK",
            "250 OK",
            "354 End data",
            "250 OK queued",
            "221 Bye",
        ]);
        smtp_conversation(&mut t, &cfg, "a@x", "b@y", "Subject: Hi\r\n\r\nbody\r\n").await.unwrap();
        (cfg, t.written)
    }

    #[test]
    fn smtp_login_transcript() {
        // Runs on any target (scripted transport, no sockets).
        let rt = tokio_test_runtime();
        let (_cfg, written) = rt.block_on(run_login_flow());
        let joined = written.join("\n");
        assert!(joined.contains("EHLO pds"));
        assert!(joined.contains("AUTH LOGIN"));
        assert!(joined.contains("MAIL FROM:<a@x>"));
        assert!(joined.contains("RCPT TO:<b@y>"));
        assert!(joined.contains("DATA"));
        assert!(written.last().unwrap() == "QUIT");
    }

    #[test]
    fn starttls_signals_upgrade() {
        let rt = tokio_test_runtime();
        let mut cfg = test_cfg();
        cfg.implicit_tls = false;
        let mut t = ScriptTransport::new(&["220 hi", "250-AUTH PLAIN", "250 STARTTLS"]);
        let err = rt.block_on(smtp_conversation(&mut t, &cfg, "a@x", "b@y", "x")).unwrap_err();
        assert_eq!(err, "STARTTLS-UPGRADE");
    }

    /// Minimal current-thread runtime for async unit tests (host only).
    fn tokio_test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }
}

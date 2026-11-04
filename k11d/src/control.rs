//! The control token. Reading the record over the API is open to the host;
//! changing the watch list or the policy needs the token. Anything on this
//! machine can reach 127.0.0.1, the recorded agent included, so the token is
//! never logged: it lives in root-only files, one holding the dashboard URL
//! that `k11 dashboard` (and `k11 daemon --open`) hand to the browser.
//!
//! It outlives the daemon, so a browser that has it keeps control across
//! restarts; deleting `TOKEN_PATH` revokes it everywhere at the next start.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tonic::Request;
use tracing::warn;

pub const TOKEN_PATH: &str = "/var/lib/k11/token";

pub struct Token(String);

impl Token {
    /// The kept token, or a new one, kept from now on.
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) if is_token(text.trim()) => return Ok(Self(text.trim().into())),
            Ok(_) => warn!(path = %path.display(), "not a control token; making a new one"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        }
        let token = Self::generate()?;
        crate::state::write_private(path, &format!("{}\n", token.0))?;
        Ok(token)
    }

    fn generate() -> Result<Self> {
        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .context("reading /dev/urandom")?;
        Ok(Self(bytes.iter().map(|b| format!("{b:02x}")).collect()))
    }

    /// The dashboard URL with control.
    pub fn url(&self, base: &str) -> String {
        format!("{base}/#token={}", self.0)
    }

    /// Store the control URL where only root can read it.
    pub fn publish(&self, path: &Path, base: &str) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let _ = std::fs::remove_file(path);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| writeln!(f, "{}", self.url(base)))
            .with_context(|| format!("writing {}", path.display()))
    }

    /// The request carries `authorization: Bearer <token>`.
    pub fn admits<T>(&self, req: &Request<T>) -> bool {
        let Some(given) = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return false;
        };
        // Constant time: the comparison leaks no prefix length.
        given.len() == self.0.len()
            && given
                .bytes()
                .zip(self.0.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }
}

fn is_token(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Next to the session socket: one runtime directory for the daemon.
pub fn url_path(socket: &Path) -> PathBuf {
    socket.with_file_name("dashboard")
}

/// `k11 dashboard`: open the dashboard with control.
pub fn open_dashboard(socket: &Path) -> Result<()> {
    let path = url_path(socket);
    let url = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "reading {} (is the daemon running? this needs root)",
            path.display()
        )
    })?;
    let url = url.trim();
    println!("{url}");
    crate::web::open_browser(url);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_only_the_token() {
        let token = Token("abc123".into());
        let mut req = Request::new(());
        assert!(!token.admits(&req));
        req.metadata_mut()
            .insert("authorization", "Bearer abc124".parse().unwrap());
        assert!(!token.admits(&req));
        req.metadata_mut()
            .insert("authorization", "Bearer abc123".parse().unwrap());
        assert!(token.admits(&req));
    }

    #[test]
    fn the_token_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("k11-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("k11").join("token");
        let first = Token::load_or_generate(&path).unwrap();
        assert!(is_token(&first.0));
        assert_eq!(Token::load_or_generate(&path).unwrap().0, first.0);
        std::fs::write(&path, "not a token\n").unwrap();
        let replaced = Token::load_or_generate(&path).unwrap();
        assert!(is_token(&replaced.0) && replaced.0 != first.0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! The control token. Reading the record over the API is open to the host;
//! changing the policy needs the token. Anything on this machine can reach
//! 127.0.0.1, the recorded agent included, so the token is never logged: it
//! lives in a root-only file holding the dashboard URL, which `k11 dashboard`
//! (and `k11 daemon --open`) hand to the browser.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tonic::Request;

pub struct Token(String);

impl Token {
    pub fn generate() -> Result<Self> {
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
}

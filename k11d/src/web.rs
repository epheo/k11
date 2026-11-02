//! Embedded dashboard serving and browser launch.
//!
//! Release builds carry k11-web/dist inside the binary; debug builds read it
//! from disk so UI iteration does not require a daemon rebuild.

use std::borrow::Cow;

use axum::body::Body;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;
use tracing::info;

#[derive(RustEmbed)]
#[folder = "../k11-web/dist"]
struct Assets;

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript",
        Some("css") => "text/css",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("json") | Some("map") => "application/json",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// Serve the embedded dashboard. Hashed assets/* are immutable-cacheable;
/// extensionless unknown paths fall back to index.html (SPA routing).
pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    let resolved = match Assets::get(path) {
        Some(file) => Some((path, file)),
        None if !path.contains('.') => Assets::get("index.html").map(|f| ("index.html", f)),
        None => None,
    };

    match resolved {
        Some((path, file)) => {
            let cache = if path.starts_with("assets/") {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            };
            // Embedded assets are static bytes: serve them without a copy.
            let body = match file.data {
                Cow::Borrowed(bytes) => Body::from(bytes),
                Cow::Owned(bytes) => Body::from(bytes),
            };
            (
                [
                    (header::CONTENT_TYPE, content_type(path)),
                    (header::CACHE_CONTROL, cache),
                ],
                body,
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            "k11 dashboard assets not found — build them with: cargo xtask build\n",
        )
            .into_response(),
    }
}

/// Best-effort browser launch for --open.
///
/// Under sudo, xdg-open must run inside the invoking user's session (the
/// systemd user manager holds DISPLAY/WAYLAND_DISPLAY; root's env does not),
/// hence systemd-run --machine=<user>@.host --user. The URL is always logged
/// so a failed launch costs nothing.
pub fn open_browser(url: &str) {
    let spawned = match std::env::var("SUDO_USER") {
        Ok(user) if user != "root" => std::process::Command::new("systemd-run")
            .args([
                "--quiet",
                "--collect",
                &format!("--machine={user}@.host"),
                "--user",
                "xdg-open",
                url,
            ])
            .spawn(),
        _ => std::process::Command::new("xdg-open").arg(url).spawn(),
    };
    match spawned {
        Ok(mut child) => {
            // Reap in the background so no zombie lingers for the daemon's lifetime.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => info!(error = %e, "could not launch a browser — open the url manually"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn get(path: &str) -> Response {
        static_handler(Uri::try_from(path).unwrap()).await
    }

    fn header_str<'a>(resp: &'a Response, name: &header::HeaderName) -> &'a str {
        resp.headers().get(name).unwrap().to_str().unwrap()
    }

    #[tokio::test]
    async fn serves_index_at_root() {
        let resp = get("/").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(header_str(&resp, &header::CONTENT_TYPE).starts_with("text/html"));
        assert_eq!(header_str(&resp, &header::CACHE_CONTROL), "no-cache");
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("<div id=\"app\">"));
    }

    #[tokio::test]
    async fn spa_fallback_for_extensionless_paths() {
        let resp = get("/some/client/route").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(header_str(&resp, &header::CONTENT_TYPE).starts_with("text/html"));
    }

    #[tokio::test]
    async fn missing_asset_is_404_not_index() {
        let resp = get("/assets/nope.js").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn hashed_assets_are_immutable() {
        // Find the real hashed css name from the built dist.
        let css = Assets::iter()
            .find(|p| p.starts_with("assets/") && p.ends_with(".css"))
            .expect("built dist should contain a hashed css");
        let resp = get(&format!("/{css}")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header_str(&resp, &header::CONTENT_TYPE), "text/css");
        assert!(header_str(&resp, &header::CACHE_CONTROL).contains("immutable"));
    }
}

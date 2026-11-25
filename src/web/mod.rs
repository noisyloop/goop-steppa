//! Local web dashboard. Bound to 127.0.0.1 only.
//!
//! Threat model: any web page you visit can make your browser talk to 127.0.0.1, and can make your
//! machine resolve any hostname. So:
//!   * Host header must be a loopback name+port (blocks DNS rebinding).
//!   * Mutating requests must carry a custom header + JSON content type (forces a CORS preflight,
//!     which we never grant) and any Origin must match the Host (blocks CSRF).
//!   * The UI renders domains with textContent only, under a strict CSP; names are also sanitised
//!     before they are ever stored.

use crate::category::Category;
use crate::event::EventTx;
use crate::filter::{parse::domain_from_input, Filter};
use crate::report::{parse_window, since_ms};
use crate::store::Store;
use anyhow::{Context, Result};
use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

pub struct WebState {
    pub store: Arc<Store>,
    pub filter: Arc<Filter>,
    pub events: EventTx,
    pub port: u16,
}

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub fn router(state: Arc<WebState>) -> Router {
    Router::new()
        .route("/", get(|| async { asset("text/html; charset=utf-8", include_str!("index.html")) }))
        .route("/app.js", get(|| async { asset("text/javascript; charset=utf-8", include_str!("app.js")) }))
        .route("/app.css", get(|| async { asset("text/css; charset=utf-8", include_str!("app.css")) }))
        .route("/api/summary", get(summary))
        .route("/api/top", get(top))
        .route("/api/timeline", get(timeline))
        .route("/api/recent", get(recent))
        .route("/api/events", get(events))
        .route("/api/block", post(block))
        .route("/api/allow", post(allow))
        .route("/api/forget", post(forget))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

fn asset(ct: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, ct)], body).into_response()
}

fn host_ok(host: &str, port: u16) -> bool {
    [format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")].iter().any(|h| h.eq_ignore_ascii_case(host))
}

/// Security gate + response hardening headers.
async fn guard(State(st): State<Arc<WebState>>, req: Request, next: Next) -> Response {
    let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !host_ok(host, st.port) {
        return (StatusCode::MISDIRECTED_REQUEST, "bad host").into_response();
    }
    if req.method() != Method::GET && req.method() != Method::HEAD {
        let h = req.headers();
        let json_ct = h.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|v| v.starts_with("application/json")).unwrap_or(false);
        let has_marker = h.get("x-goop-steppa").map(|v| v == "1").unwrap_or(false);
        if !json_ct || !has_marker {
            return (StatusCode::FORBIDDEN, "missing required headers").into_response();
        }
        if let Some(origin) = h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            let o = origin.strip_prefix("http://").unwrap_or("");
            if !o.eq_ignore_ascii_case(host) {
                return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
            }
        }
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

type ApiResult = Result<Json<Value>, (StatusCode, String)>;

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn bad(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.to_string())
}

#[derive(Deserialize)]
struct WindowQ {
    since: Option<String>,
    limit: Option<usize>,
    category: Option<String>,
}

fn window(q: &WindowQ) -> Result<(i64, i64), (StatusCode, String)> {
    let w = parse_window(q.since.as_deref().unwrap_or("24h")).map_err(bad)?;
    Ok((w, since_ms(w, chrono::Utc::now().timestamp_millis())))
}

/// Run a blocking SQLite query off the async worker threads.
async fn db<T: Send + 'static>(st: &Arc<WebState>, f: impl FnOnce(&Store) -> Result<T> + Send + 'static) -> Result<T, (StatusCode, String)> {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || f(&store)).await.map_err(internal)?.map_err(internal)
}

async fn summary(State(st): State<Arc<WebState>>, Query(q): Query<WindowQ>) -> ApiResult {
    let (_, since) = window(&q)?;
    let totals = db(&st, move |s| s.totals(since)).await?;
    let mut cats: HashMap<&str, (u64, u64)> = Category::ALL.iter().map(|c| (c.as_str(), (0, 0))).collect();
    let (mut total, mut blocked) = (0u64, 0u64);
    for (c, a, n) in totals {
        let e = cats.entry(c.as_str()).or_default();
        if a == crate::category::Action::Blocked {
            e.0 += n;
            blocked += n;
        } else {
            e.1 += n;
        }
        total += n;
    }
    let cats: Value = cats.into_iter().map(|(k, (b, a))| (k.to_string(), json!({"blocked": b, "allowed": a}))).collect::<serde_json::Map<_, _>>().into();
    Ok(Json(json!({"total": total, "blocked": blocked, "categories": cats})))
}

async fn top(State(st): State<Arc<WebState>>, Query(q): Query<WindowQ>) -> ApiResult {
    let (_, since) = window(&q)?;
    let limit = q.limit.unwrap_or(8).clamp(1, 50);
    let all = db(&st, move |s| {
        let mut m = serde_json::Map::new();
        for c in Category::ALL {
            let rows = s.top_domains(since, c, limit)?;
            m.insert(c.as_str().into(), rows.into_iter().map(|(d, n)| json!({"domain": d, "count": n})).collect::<Vec<_>>().into());
        }
        Ok(m)
    })
    .await?;
    Ok(Json(all.into()))
}

async fn timeline(State(st): State<Arc<WebState>>, Query(q): Query<WindowQ>) -> ApiResult {
    let (w, since) = window(&q)?;
    let now = chrono::Utc::now().timestamp_millis();
    let span = if w == i64::MAX { 30 * 86_400_000 } else { w };
    let since = if w == i64::MAX { now - span } else { since };
    // ~48 buckets, at least a minute wide.
    let bucket = (span / 48).max(60_000);
    let rows = db(&st, move |s| s.timeline(since, bucket)).await?;
    Ok(Json(json!({
        "bucket_ms": bucket, "since_ms": since, "now_ms": now,
        "points": rows.into_iter().map(|(t, b, a)| json!({"t": t, "blocked": b, "allowed": a})).collect::<Vec<_>>(),
    })))
}

async fn recent(State(st): State<Arc<WebState>>, Query(q): Query<WindowQ>) -> ApiResult {
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let cat: Option<Category> = match q.category.as_deref() {
        Some(c) => Some(c.parse().map_err(bad)?),
        None => None,
    };
    let rows = db(&st, move |s| s.recent(0, limit, cat)).await?;
    Ok(Json(serde_json::to_value(rows).map_err(internal)?))
}

async fn events(State(st): State<Arc<WebState>>) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(st.events.subscribe()).filter_map(|r| match r {
        Ok(ev) => Event::default().json_data(&ev).ok().map(Ok),
        Err(_) => None, // lagged: skip
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[derive(Deserialize)]
struct DomainBody {
    domain: String,
    category: Option<String>,
}

fn dom(b: &DomainBody) -> Result<String, (StatusCode, String)> {
    domain_from_input(&b.domain).ok_or_else(|| bad(format!("'{}' is not a valid domain", b.domain.chars().take(80).collect::<String>())))
}

async fn block(State(st): State<Arc<WebState>>, Json(b): Json<DomainBody>) -> ApiResult {
    let d = dom(&b)?;
    let cat = match b.category.as_deref() {
        Some(c) => c.parse::<Category>().map_err(bad)?,
        None => Category::Ads,
    };
    if !cat.is_blockable() {
        return Err(bad("category must be malware, telemetry or ads"));
    }
    st.filter.block(&d, cat).map_err(internal)?;
    Ok(Json(json!({"ok": true, "domain": d, "action": "blocked", "category": cat})))
}

async fn allow(State(st): State<Arc<WebState>>, Json(b): Json<DomainBody>) -> ApiResult {
    let d = dom(&b)?;
    st.filter.allow(&d).map_err(internal)?;
    Ok(Json(json!({"ok": true, "domain": d, "action": "allowed"})))
}

async fn forget(State(st): State<Arc<WebState>>, Json(b): Json<DomainBody>) -> ApiResult {
    let d = dom(&b)?;
    st.filter.forget(&d).map_err(internal)?;
    Ok(Json(json!({"ok": true, "domain": d, "action": "forgotten"})))
}

/// Bind 127.0.0.1:port (never any other interface) and serve until `shutdown`.
pub async fn serve(port: u16, state: Arc<WebState>, shutdown: impl std::future::Future<Output = ()> + Send + 'static) -> Result<()> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("binding dashboard on {addr}"))?;
    tracing::info!("dashboard at http://{addr}/");
    axum::serve(listener, router(state)).with_graceful_shutdown(shutdown).await.context("dashboard stopped")
}

#[cfg(test)]
mod tests;

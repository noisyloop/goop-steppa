use super::*;
use crate::category::{Action, Verdict};
use crate::config::Config;
use crate::event::QueryEvent;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

const PORT: u16 = 8053;

fn setup(name: &str) -> (Router, Arc<WebState>) {
    let d = std::env::temp_dir().join(format!("goop-web-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let filter = Arc::new(Filter::with_paths(&Config::default(), d.join("c"), d.join("b.txt"), d.join("a.txt")).unwrap());
    let store = Arc::new(Store::open_memory().unwrap());
    let mk = |dom: &str, a: Action, c: Category| QueryEvent::new(dom, "A", &Verdict { action: a, category: c, source: Some("L".into()) }, "127.0.0.1".parse().unwrap());
    store
        .insert_batch(&[
            mk("track.io", Action::Blocked, Category::Ads),
            mk("track.io", Action::Blocked, Category::Ads),
            mk("evil.com", Action::Blocked, Category::Malware),
            mk("good.org", Action::Allowed, Category::Clean),
        ])
        .unwrap();
    let st = Arc::new(WebState { store, filter, events: crate::event::channel(), port: PORT });
    (router(st.clone()), st)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).header("host", format!("127.0.0.1:{PORT}")).body(Body::empty()).unwrap()
}

fn post(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", format!("127.0.0.1:{PORT}"))
        .header("content-type", "application/json")
        .header("x-goop-steppa", "1")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn json_of(r: Response) -> Value {
    serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn serves_dashboard_with_hardening_headers() {
    let (app, _) = setup("static");
    for path in ["/", "/app.js", "/app.css"] {
        let r = app.clone().oneshot(get(path)).await.unwrap();
        assert_eq!(r.status(), 200, "{path}");
        let csp = r.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_string();
        assert!(csp.contains("default-src 'none'") && csp.contains("script-src 'self'") && !csp.contains("unsafe-inline"));
        assert_eq!(r.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }
}

#[tokio::test]
async fn ui_never_uses_innerhtml_or_external_resources() {
    let js = include_str!("app.js");
    for bad in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "http://", "https://"] {
        assert!(!js.contains(bad), "app.js must not contain {bad}");
    }
    let html = include_str!("index.html");
    assert!(!html.contains("http://") && !html.contains("https://"), "no external resources");
    assert!(!html.contains("<script>") && !html.contains(" onclick"), "no inline script");
}

#[tokio::test]
async fn rejects_foreign_host_header_dns_rebinding() {
    let (app, _) = setup("rebind");
    for host in ["evil.example.com", "evil.example.com:8053", "127.0.0.1", "127.0.0.1:9999", ""] {
        let req = Request::builder().uri("/api/summary").header("host", host).body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), 421, "host {host:?}");
    }
    for host in ["localhost:8053", "LOCALHOST:8053", "[::1]:8053"] {
        let req = Request::builder().uri("/api/summary").header("host", host).body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), 200, "host {host:?}");
    }
}

#[tokio::test]
async fn mutations_require_marker_header_and_json() {
    let (app, st) = setup("csrf");
    let body = r#"{"domain":"victim.com"}"#;
    // classic cross-site form post: no marker header, form content type
    let r = Request::builder().method("POST").uri("/api/allow").header("host", format!("127.0.0.1:{PORT}")).header("content-type", "application/x-www-form-urlencoded").body(Body::from(body)).unwrap();
    assert_eq!(app.clone().oneshot(r).await.unwrap().status(), 403);
    // text/plain "simple request" with marker still refused (wrong content type)
    let r = Request::builder().method("POST").uri("/api/allow").header("host", format!("127.0.0.1:{PORT}")).header("content-type", "text/plain").header("x-goop-steppa", "1").body(Body::from(body)).unwrap();
    assert_eq!(app.clone().oneshot(r).await.unwrap().status(), 403);
    // json but no marker
    let r = Request::builder().method("POST").uri("/api/allow").header("host", format!("127.0.0.1:{PORT}")).header("content-type", "application/json").body(Body::from(body)).unwrap();
    assert_eq!(app.clone().oneshot(r).await.unwrap().status(), 403);
    // cross-origin even with headers
    let mut r = post("/api/allow", body);
    r.headers_mut().insert("origin", "http://evil.example.com".parse().unwrap());
    assert_eq!(app.clone().oneshot(r).await.unwrap().status(), 403);
    assert_eq!(st.filter.check("victim.com").action, Action::Allowed); // nothing was blocked/allowed by any of that
    assert_eq!(st.filter.stats().1, (0, 0), "user lists must be untouched");
    // same-origin works
    let mut r = post("/api/allow", body);
    r.headers_mut().insert("origin", format!("http://127.0.0.1:{PORT}").parse().unwrap());
    assert_eq!(app.clone().oneshot(r).await.unwrap().status(), 200);
    assert_eq!(st.filter.stats().1, (0, 1));
}

#[tokio::test]
async fn block_allow_forget_take_effect_immediately() {
    let (app, st) = setup("actions");
    let r = app.clone().oneshot(post("/api/block", r#"{"domain":"https://Tracker.Example/x","category":"telemetry"}"#)).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(json_of(r).await["domain"], "tracker.example");
    let v = st.filter.check("a.tracker.example");
    assert_eq!((v.action, v.category), (Action::Blocked, Category::Telemetry));

    assert_eq!(app.clone().oneshot(post("/api/allow", r#"{"domain":"tracker.example"}"#)).await.unwrap().status(), 200);
    assert_eq!(st.filter.check("a.tracker.example").action, Action::Allowed);

    assert_eq!(app.clone().oneshot(post("/api/forget", r#"{"domain":"tracker.example"}"#)).await.unwrap().status(), 200);
    assert_eq!(st.filter.stats().1, (0, 0));
}

#[tokio::test]
async fn action_input_validation() {
    let (app, _) = setup("validate");
    for (uri, body) in [
        ("/api/block", r#"{"domain":"<script>alert(1)</script>"}"#),
        ("/api/block", r#"{"domain":"nodots"}"#),
        ("/api/block", r#"{"domain":"a.com","category":"clean"}"#),
        ("/api/block", r#"{"domain":"a.com","category":"bogus"}"#),
        ("/api/allow", r#"{"domain":""}"#),
    ] {
        assert_eq!(app.clone().oneshot(post(uri, body)).await.unwrap().status(), 400, "{uri} {body}");
    }
    assert_eq!(app.clone().oneshot(post("/api/allow", "not json")).await.unwrap().status(), 400);
    assert_eq!(app.clone().oneshot(get("/api/summary?since=bogus")).await.unwrap().status(), 400);
}

#[tokio::test]
async fn read_endpoints_return_expected_data() {
    let (app, _) = setup("read");
    let s = json_of(app.clone().oneshot(get("/api/summary?since=all")).await.unwrap()).await;
    assert_eq!(s["total"], 4);
    assert_eq!(s["blocked"], 3);
    assert_eq!(s["categories"]["ads"]["blocked"], 2);
    assert_eq!(s["categories"]["telemetry"]["blocked"], 0);

    let t = json_of(app.clone().oneshot(get("/api/top?since=all&limit=5")).await.unwrap()).await;
    assert_eq!(t["ads"][0]["domain"], "track.io");
    assert_eq!(t["ads"][0]["count"], 2);
    assert_eq!(t["malware"][0]["domain"], "evil.com");
    assert!(t["telemetry"].as_array().unwrap().is_empty());

    let r = json_of(app.clone().oneshot(get("/api/recent?limit=2")).await.unwrap()).await;
    assert_eq!(r.as_array().unwrap().len(), 2);
    assert_eq!(r[0]["domain"], "good.org");
    let r = json_of(app.clone().oneshot(get("/api/recent?category=malware")).await.unwrap()).await;
    assert_eq!(r.as_array().unwrap().len(), 1);

    let tl = json_of(app.clone().oneshot(get("/api/timeline?since=1h")).await.unwrap()).await;
    let total: u64 = tl["points"].as_array().unwrap().iter().map(|p| p["blocked"].as_u64().unwrap() + p["allowed"].as_u64().unwrap()).sum();
    assert_eq!(total, 4);
}

#[tokio::test]
async fn sse_streams_live_events() {
    let (app, st) = setup("sse");
    let resp = app.clone().oneshot(get("/api/events")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/event-stream"));
    let mut body = resp.into_body();
    let v = Verdict { action: Action::Blocked, category: Category::Malware, source: Some("L".into()) };
    st.events.send(QueryEvent::new("live.example.com", "A", &v, "127.0.0.1".parse().unwrap())).unwrap();
    let frame = tokio::time::timeout(std::time::Duration::from_secs(3), body.frame()).await.expect("no SSE frame").unwrap().unwrap();
    let text = String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap();
    assert!(text.contains("live.example.com") && text.contains("\"malware\""), "{text}");
}

#[test]
fn host_check_is_exact() {
    assert!(host_ok("127.0.0.1:8053", 8053));
    assert!(!host_ok("127.0.0.1:8053.evil.com", 8053));
    assert!(!host_ok("evil.com/127.0.0.1:8053", 8053));
}

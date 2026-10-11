//! avhsol-proxy: sits between a pi agent and the LLM.
//!   POST /v1/chat/completions   forward to $AVHSOL_UPSTREAM, sanitising untrusted tool results first
//!   POST /v1/guard/tool         tool-call decision (called from pi's beforeToolCall hook)
//!   GET|POST /v1/guard/mode     off | monitor | enforce
//!   GET|POST /v1/guard/policy   current policy (JSON); scenario capabilities are pushed here
//!   GET /v1/guard/events        recent decisions;  GET /metrics
mod anthropic;
mod state;
mod wire;

use avhsol_guard::sanitize::sanitize_tool_result;
use avhsol_guard::{decide, GuardRequest, Policy};
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use state::{Mode, Shared};
use std::sync::Arc;
use std::time::Instant;

/// AVHSOL_<NAME>, falling back to the old AGENTBREAK_<NAME> so existing setups keep working.
fn env_var(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(format!("AVHSOL_{name}")).or_else(|_| std::env::var(format!("AGENTBREAK_{name}")))
}

#[tokio::main]
async fn main() {
    let addr = env_var("GUARD_ADDR").unwrap_or_else(|_| "127.0.0.1:7077".into());
    let upstream = env_var("UPSTREAM").unwrap_or_default();
    let policy = match env_var("POLICY") {
        Ok(path) => {
            let s = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            Policy::from_yaml(&s).unwrap_or_else(|e| panic!("parse {path}: {e}"))
        }
        Err(_) => Policy::default(),
    };
    let mode = env_var("GUARD_MODE").ok().and_then(|m| Mode::parse(&m)).unwrap_or(Mode::Enforce);
    let shared = Arc::new(Shared::new(policy, mode, upstream.clone()));

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics))
        .route("/v1/guard/tool", post(guard_tool))
        .route("/v1/guard/mode", get(get_mode).post(set_mode))
        .route("/v1/guard/policy", get(get_policy).post(set_policy))
        .route("/v1/guard/events", get(events))
        .route("/v1/guard/reset", post(reset))
        .route("/v1/guard/cassette", get(get_cassette).post(set_cassette))
        .route("/v1/guard/exchanges", get(exchanges))
        .route("/v1/chat/completions", post(chat))
        .route("/chat/completions", post(chat))
        .route("/v1/messages", post(messages))
        .fallback(passthrough)
        .with_state(shared);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    eprintln!("avhsol-proxy listening on http://{addr} (mode={}, upstream={})", mode.as_str(), if upstream.is_empty() { "<none>" } else { &upstream });
    axum::serve(listener, app).await.unwrap();
}

async fn guard_tool(State(s): State<Arc<Shared>>, Json(req): Json<GuardRequest>) -> Json<Value> {
    let t0 = Instant::now();
    let policy = s.policy.read().unwrap().clone();
    let d = decide(&policy, &req);
    let micros = t0.elapsed().as_micros() as u64;
    s.record_decision(&req, &d, micros);
    Json(serde_json::to_value(&d).unwrap())
}

async fn get_mode(State(s): State<Arc<Shared>>) -> Json<Value> {
    Json(json!({"mode": s.mode().as_str()}))
}

#[derive(Deserialize)]
struct ModeBody {
    mode: String,
}

async fn set_mode(State(s): State<Arc<Shared>>, Json(b): Json<ModeBody>) -> Response {
    match Mode::parse(&b.mode) {
        Some(m) => {
            s.set_mode(m);
            Json(json!({"mode": m.as_str()})).into_response()
        }
        None => (StatusCode::BAD_REQUEST, "mode must be off|monitor|enforce").into_response(),
    }
}

async fn get_policy(State(s): State<Arc<Shared>>) -> Json<Value> {
    let p = s.policy.read().unwrap();
    Json(json!({"policy": &*p, "fingerprint": p.fingerprint()}))
}

async fn set_policy(State(s): State<Arc<Shared>>, Json(p): Json<Policy>) -> Json<Value> {
    let fp = p.fingerprint();
    *s.policy.write().unwrap() = p;
    Json(json!({"fingerprint": fp}))
}

#[derive(Deserialize)]
struct EventsQuery {
    since: Option<u64>,
}

async fn events(State(s): State<Arc<Shared>>, Query(q): Query<EventsQuery>) -> Json<Value> {
    Json(json!({"events": s.events_since(q.since.unwrap_or(0))}))
}

async fn exchanges(State(s): State<Arc<Shared>>, Query(q): Query<EventsQuery>) -> Json<Value> {
    Json(json!({"exchanges": s.exchanges_since(q.since.unwrap_or(0))}))
}

/// Anything that is not a chat completion (model listing, etc.) is forwarded untouched.
async fn passthrough(State(s): State<Arc<Shared>>, req: axum::extract::Request) -> Response {
    if s.upstream.is_empty() {
        return (StatusCode::BAD_GATEWAY, "AVHSOL_UPSTREAM is not set").into_response();
    }
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, 8 << 20).await {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let path = parts.uri.path().strip_prefix("/v1").unwrap_or(parts.uri.path());
    let q = parts.uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let url = format!("{}{}{}", s.upstream.trim_end_matches('/'), path, q);
    let mut rb = s.http.request(parts.method.clone(), url).body(bytes);
    if let Some(a) = parts.headers.get(header::AUTHORIZATION) {
        rb = rb.header(header::AUTHORIZATION, a);
    }
    match rb.send().await {
        Ok(up) => {
            let status = StatusCode::from_u16(up.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let ct = up.headers().get(header::CONTENT_TYPE).cloned();
            let body = up.bytes().await.unwrap_or_default();
            let mut r = Response::new(Body::from(body));
            *r.status_mut() = status;
            if let Some(ct) = ct {
                r.headers_mut().insert(header::CONTENT_TYPE, ct);
            }
            r
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("upstream: {e}")).into_response(),
    }
}

async fn reset(State(s): State<Arc<Shared>>) -> Json<Value> {
    s.reset_metrics();
    Json(json!({"ok": true}))
}

#[derive(Deserialize)]
struct CassetteBody {
    exchanges: Vec<Value>,
}

/// Loads recorded model answers: the next N model calls get these (in order) instead of reaching the model, so a
/// closed-box agent re-walks a recorded run up to a chosen point and the live model takes over after it.
async fn set_cassette(State(s): State<Arc<Shared>>, Json(b): Json<CassetteBody>) -> Json<Value> {
    s.set_cassette(b.exchanges);
    Json(json!({"remaining": s.cassette_len()}))
}

async fn get_cassette(State(s): State<Arc<Shared>>) -> Json<Value> {
    Json(json!({"remaining": s.cassette_len()}))
}

/// Builds the OpenAI-shaped answer for a recorded exchange {text, tool_calls:[{id,name,args}]}.
fn cassette_response(rec: &Value) -> Value {
    let text = rec.get("text").and_then(Value::as_str).unwrap_or("");
    let calls: Vec<Value> = rec
        .get("tool_calls")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|c| {
            json!({"id": c.get("id").cloned().unwrap_or(json!("call_cassette")), "type": "function",
                   "function": {"name": c.get("name").cloned().unwrap_or(json!("")),
                                "arguments": serde_json::to_string(c.get("args").unwrap_or(&json!({}))).unwrap_or_else(|_| "{}".into())}})
        })
        .collect();
    let mut msg = json!({"role": "assistant", "content": if text.is_empty() && !calls.is_empty() { Value::Null } else { json!(text) }});
    let has_calls = !calls.is_empty();
    if has_calls {
        msg["tool_calls"] = Value::Array(calls);
    }
    json!({"id": "chatcmpl-cassette", "object": "chat.completion", "model": "cassette", "created": 0,
           "choices": [{"index": 0, "finish_reason": if has_calls { "tool_calls" } else { "stop" }, "message": msg}],
           "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}})
}

async fn metrics(State(s): State<Arc<Shared>>) -> Json<Value> {
    Json(s.metrics_json())
}

/// Sanitise untrusted tool results in an outgoing chat request (D1 fence, D2 strip hidden).
fn sanitize_request(s: &Shared, body: &mut Value) {
    let policy = s.policy.read().unwrap().clone();
    let do_fence = policy.enabled("D1", &[]);
    let do_strip = policy.enabled("D2", &[]);
    if !do_fence && !do_strip {
        return;
    }
    let Some(msgs) = body.get_mut("messages").and_then(Value::as_array_mut) else { return };
    // tool_call_id -> tool name, from assistant messages.
    let mut names = std::collections::HashMap::new();
    for m in msgs.iter() {
        if let Some(calls) = m.get("tool_calls").and_then(Value::as_array) {
            for c in calls {
                if let (Some(id), Some(n)) = (c.get("id").and_then(Value::as_str), c.pointer("/function/name").and_then(Value::as_str)) {
                    names.insert(id.to_string(), n.to_string());
                }
            }
        }
    }
    for m in msgs.iter_mut() {
        if m.get("role").and_then(Value::as_str) != Some("tool") {
            continue;
        }
        let id = m.get("tool_call_id").and_then(Value::as_str).unwrap_or("").to_string();
        let tool = names.get(&id).cloned().unwrap_or_default();
        let untrusted = policy.untrusted_tools.iter().any(|t| t == &tool);
        // Content may be a string or an array of {type:"text",text}.
        let raw = match m.get("content") {
            Some(Value::String(t)) => t.clone(),
            Some(Value::Array(parts)) => parts.iter().filter_map(|p| p.get("text").and_then(Value::as_str)).collect::<Vec<_>>().join(""),
            _ => continue,
        };
        let out = sanitize_tool_result(&format!("tool:{tool}"), &raw, do_strip, do_fence && untrusted);
        s.note_sanitized(out.hidden_removed, untrusted && do_fence);
        m["content"] = Value::String(out.text);
    }
}

/// The shared pipeline for both wire formats: take an OpenAI-shaped request, apply the guard (sanitise untrusted
/// results, record, strip denied tool calls) around the upstream call, and return the OpenAI-shaped answer.
/// `Err` carries a ready response for failures (including upstream non-2xx, passed through unchanged).
async fn exchange(s: &Shared, auth: Option<header::HeaderValue>, mut payload: Value) -> Result<Value, Response> {
    let t0 = Instant::now();
    if s.upstream.is_empty() {
        return Err((StatusCode::BAD_GATEWAY, "AVHSOL_UPSTREAM is not set").into_response());
    }
    let mode = s.mode();
    let policy = s.policy.read().unwrap().clone();
    // What the agent saw this turn (before any sanitising), for the trace and for provenance.
    let ctx = wire::read_request(&payload, &policy);
    // Always fetch the full answer so tool calls can be inspected before the agent receives them.
    payload["stream"] = Value::Bool(false);
    if let Some(o) = payload.as_object_mut() {
        o.remove("stream_options");
    }
    if let Some(rec) = s.pop_cassette() {
        // A replayed part of a recorded run: serve the recorded answer, never reach the model, never strip it.
        let resp = cassette_response(&rec);
        let calls: Vec<wire::ToolCallRec> = rec
            .get("tool_calls")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|c| wire::ToolCallRec {
                id: c.get("id").and_then(Value::as_str).unwrap_or("").to_string(),
                name: c.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
                args: c.get("args").cloned().unwrap_or(json!({})),
            })
            .collect();
        s.record_exchange(&ctx.tool_results, rec.get("text").and_then(Value::as_str).unwrap_or(""), &calls, &[]);
        return Ok(resp);
    }
    if mode == Mode::Enforce {
        sanitize_request(s, &mut payload);
    }
    apply_upstream_model(&mut payload, std::env::var("AVHSOL_UPSTREAM_MODEL").ok().as_deref());
    // An audited agent holds a placeholder key; the real upstream key (environment only) replaces it.
    let auth = std::env::var("AVHSOL_UPSTREAM_KEY")
        .ok()
        .filter(|k| !k.is_empty())
        .and_then(|k| format!("Bearer {k}").parse().ok())
        .or(auth);
    let url = format!("{}/chat/completions", s.upstream.trim_end_matches('/'));
    let mut rb = s.http.post(url).json(&payload);
    if let Some(a) = auth {
        rb = rb.header(header::AUTHORIZATION, a);
    }
    let up = rb.send().await.map_err(|e| (StatusCode::BAD_GATEWAY, format!("upstream: {e}")).into_response())?;
    let status = StatusCode::from_u16(up.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let ct = up.headers().get(header::CONTENT_TYPE).cloned();
    let raw = up.bytes().await.map_err(|e| (StatusCode::BAD_GATEWAY, format!("upstream body: {e}")).into_response())?;
    // time spent waiting on the model: dominated by model latency, NOT guard overhead
    s.record_proxy_overhead(t0.elapsed().as_micros() as u64);
    let raw_response = |raw: bytes::Bytes| {
        let mut r = Response::new(Body::from(raw));
        *r.status_mut() = status;
        if let Some(ct) = &ct {
            r.headers_mut().insert(header::CONTENT_TYPE, ct.clone());
        }
        r
    };
    if !status.is_success() {
        return Err(raw_response(raw));
    }
    let Ok(mut resp) = serde_json::from_slice::<Value>(&raw) else { return Err(raw_response(raw)) };
    let g0 = Instant::now();
    let done = wire::process_response(&mut resp, &ctx, &policy, mode);
    let micros = g0.elapsed().as_micros() as u64;
    for (req, d) in &done.decisions {
        s.record_decision(req, d, micros);
    }
    s.record_exchange(&ctx.tool_results, &done.text, &done.calls, &done.blocked);
    Ok(resp)
}

/// An audited agent hard-codes a model name the user's endpoint may not serve: AVHSOL_UPSTREAM_MODEL replaces it.
fn apply_upstream_model(payload: &mut Value, model: Option<&str>) {
    if let Some(m) = model.filter(|m| !m.is_empty()) {
        payload["model"] = Value::String(m.to_string());
    }
}

async fn chat(State(s): State<Arc<Shared>>, headers: HeaderMap, body: bytes::Bytes) -> Response {
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad json: {e}")).into_response(),
    };
    let wants_stream = payload.get("stream").and_then(Value::as_bool).unwrap_or(false);
    let resp = match exchange(&s, headers.get(header::AUTHORIZATION).cloned(), payload).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    if wants_stream {
        let mut r = Response::new(Body::from(wire::to_sse(&resp)));
        r.headers_mut().insert(header::CONTENT_TYPE, "text/event-stream".parse().unwrap());
        return r;
    }
    let mut r = Response::new(Body::from(serde_json::to_vec(&resp).unwrap_or_default()));
    r.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    r
}

/// Anthropic Messages API entry point (Claude Code and other Anthropic-wire agents).
/// AVHSOL_UPSTREAM_MODEL, if set, replaces the Claude model name the agent asks for.
async fn messages(State(s): State<Arc<Shared>>, headers: HeaderMap, body: bytes::Bytes) -> Response {
    let err = |status: StatusCode, kind: &str, msg: &str| {
        let mut r = Response::new(Body::from(anthropic::error_body(kind, msg).to_string()));
        *r.status_mut() = status;
        r.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        r
    };
    let areq: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::BAD_REQUEST, "invalid_request_error", &format!("bad json: {e}")),
    };
    let wants_stream = areq.get("stream").and_then(Value::as_bool).unwrap_or(false);
    let asked_model = areq.get("model").and_then(Value::as_str).unwrap_or("").to_string();
    let model_override = std::env::var("AVHSOL_UPSTREAM_MODEL").ok().filter(|m| !m.is_empty());
    let oreq = anthropic::to_openai(&areq, model_override.as_deref());
    // Anthropic SDKs authenticate with x-api-key; the upstream expects a bearer token.
    let auth = headers
        .get(header::AUTHORIZATION)
        .cloned()
        .or_else(|| headers.get("x-api-key").and_then(|k| k.to_str().ok()).and_then(|k| format!("Bearer {k}").parse().ok()));
    let resp = match exchange(&s, auth, oreq).await {
        Ok(r) => r,
        Err(r) => {
            let st = r.status();
            let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap_or_default();
            return err(st, "api_error", String::from_utf8_lossy(&b).chars().take(300).collect::<String>().as_str());
        }
    };
    let msg = anthropic::from_openai(&resp, &asked_model);
    if wants_stream {
        let mut r = Response::new(Body::from(anthropic::to_sse(&msg)));
        r.headers_mut().insert(header::CONTENT_TYPE, "text/event-stream".parse().unwrap());
        return r;
    }
    let mut r = Response::new(Body::from(msg.to_string()));
    r.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cassette_response_carries_text_and_tool_calls() {
        let r = cassette_response(&json!({"text": "", "tool_calls": [{"id": "c1", "name": "bash", "args": {"command": "ls"}}]}));
        assert_eq!(r["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(r["choices"][0]["message"]["tool_calls"][0]["function"]["name"], "bash");
        assert_eq!(r["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"], "{\"command\":\"ls\"}");
        let t = cassette_response(&json!({"text": "done", "tool_calls": []}));
        assert_eq!(t["choices"][0]["finish_reason"], "stop");
        assert_eq!(t["choices"][0]["message"]["content"], "done");
    }
}

#[cfg(test)]
mod model_override_tests {
    use super::*;

    #[test]
    fn upstream_model_replaces_the_agents_choice() {
        let mut p = json!({"model": "gpt-4o", "messages": []});
        apply_upstream_model(&mut p, Some("local-35b"));
        assert_eq!(p["model"], "local-35b");
        apply_upstream_model(&mut p, Some(""));
        assert_eq!(p["model"], "local-35b", "an empty override changes nothing");
        let mut q = json!({"model": "gpt-4o"});
        apply_upstream_model(&mut q, None);
        assert_eq!(q["model"], "gpt-4o");
    }
}

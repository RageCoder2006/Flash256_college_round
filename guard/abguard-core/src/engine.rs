//! The decision engine behind `POST /v1/guard/tool`.
//!
//! Key idea (carried over from TRIVEKTRA): the verdict never depends on what the model says.
//! It depends on provenance (was untrusted content in context?) and on the user's own words
//! (did the *user* ask for this destination?).
use crate::detect::{find_secrets, scan_text};
use crate::policy::Policy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct GuardRequest {
    #[serde(default)]
    pub episode_id: String,
    pub tool: String,
    #[serde(default)]
    pub args: Value,
    /// Provenance labels of untrusted content already in the model's context.
    #[serde(default)]
    pub untrusted_sources: Vec<String>,
    #[serde(default)]
    pub user_turns: Vec<String>,
    #[serde(default)]
    pub mode: String,
    /// Ablation: defenses to disable for this request.
    #[serde(default)]
    pub defenses_off: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionKind {
    Allow,
    Deny,
    Approve,
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub decision: DecisionKind,
    pub reason: String,
    pub rule_ids: Vec<String>,
    pub flags: Vec<String>,
}

fn arg_str<'a>(args: &'a Value, k: &str) -> &'a str {
    args.get(k).and_then(Value::as_str).unwrap_or("")
}

fn email_domain(addr: &str) -> String {
    addr.rsplit_once('@').map(|(_, d)| d.trim().to_lowercase()).unwrap_or_default()
}

fn url_host(u: &str) -> String {
    let rest = u.split_once("://").map(|(_, r)| r).unwrap_or(u);
    rest.split(|c| c == '/' || c == '?' || c == '#' || c == ':').next().unwrap_or("").to_lowercase()
}

/// Destination string(s) an egress call would send to.
fn destinations(tool: &str, args: &Value) -> Vec<String> {
    match tool {
        "send_email" => vec![arg_str(args, "to").to_lowercase()],
        "http_fetch" => vec![url_host(arg_str(args, "url"))],
        _ => vec![],
    }
}

/// True if the user's own turns name every destination of the call.
fn user_named(dests: &[String], user_turns: &[String]) -> bool {
    if dests.is_empty() || dests.iter().any(|d| d.is_empty()) {
        return false;
    }
    let hay: String = user_turns.join("\n").to_lowercase();
    dests.iter().all(|d| hay.contains(d.as_str()))
}

fn all_args_text(args: &Value) -> String {
    match args {
        Value::String(s) => s.clone(),
        Value::Object(m) => m.values().map(all_args_text).collect::<Vec<_>>().join("\n"),
        Value::Array(a) => a.iter().map(all_args_text).collect::<Vec<_>>().join("\n"),
        other => other.to_string(),
    }
}

pub fn decide(policy: &Policy, req: &GuardRequest) -> Decision {
    let off = &req.defenses_off;
    let is_egress = policy.egress_tools.iter().any(|t| t == &req.tool);
    let mut rule_ids: Vec<String> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    let mut kind = DecisionKind::Allow;
    let mut flags: Vec<String> = Vec::new();

    let deny = |id: &str, why: String, rule_ids: &mut Vec<String>, reasons: &mut Vec<String>, kind: &mut DecisionKind| {
        rule_ids.push(id.to_string());
        reasons.push(why);
        *kind = DecisionKind::Deny;
    };

    // D3: capability boundary, independent of provenance.
    if policy.enabled("D3", off) {
        if let Some(cap) = policy.capabilities.get(&req.tool) {
            if req.tool == "send_email" && !cap.allowed_recipient_domains.is_empty() {
                let d = email_domain(arg_str(&req.args, "to"));
                if !cap.allowed_recipient_domains.iter().any(|a| a.to_lowercase() == d) {
                    deny("D3", format!("recipient domain '{d}' is outside the allowed set"), &mut rule_ids, &mut reasons, &mut kind);
                }
            }
            if req.tool == "http_fetch" && !cap.allowed_hosts.is_empty() {
                let h = url_host(arg_str(&req.args, "url"));
                if !cap.allowed_hosts.iter().any(|a| a.to_lowercase() == h) {
                    deny("D3", format!("host '{h}' is not on the allow-list"), &mut rule_ids, &mut reasons, &mut kind);
                }
            }
        }
    }

    // D7: destructive tools need a human.
    if policy.enabled("D7", off) && policy.destructive_tools.iter().any(|t| t == &req.tool) {
        rule_ids.push("D7".into());
        reasons.push(format!("tool '{}' is destructive and needs human approval", req.tool));
        if kind == DecisionKind::Allow {
            kind = DecisionKind::Approve;
        }
    }

    if is_egress {
        let dests = destinations(&req.tool, &req.args);
        let named = user_named(&dests, &req.user_turns);

        // D4: taint-based egress. Untrusted content in context + a destination the user never named.
        if policy.enabled("D4", off) && !req.untrusted_sources.is_empty() && !named {
            deny(
                "D4",
                format!(
                    "egress via '{}' after untrusted content ({}) to a destination the user did not request",
                    req.tool,
                    req.untrusted_sources.join(", ")
                ),
                &mut rule_ids,
                &mut reasons,
                &mut kind,
            );
        }

        // D5: secret-looking material must not leave, unless the user named the destination.
        if policy.enabled("D5", off) {
            let text = all_args_text(&req.args);
            let secrets = find_secrets(&text);
            if !secrets.is_empty() && !named {
                deny("D5", format!("outbound arguments contain secret material ({})", secrets.join(", ")), &mut rule_ids, &mut reasons, &mut kind);
            }
        }
    }

    // D2: content flags in the *arguments* the model produced (an injected instruction often reappears verbatim).
    if policy.enabled("D2", off) {
        let f = scan_text(&all_args_text(&req.args));
        flags = f.iter().map(|s| s.to_string()).collect();
        if is_egress && !flags.is_empty() && !req.untrusted_sources.is_empty() {
            deny("D2", format!("outbound arguments carry injection markers ({})", flags.join(", ")), &mut rule_ids, &mut reasons, &mut kind);
        }
    }

    rule_ids.dedup();
    Decision {
        decision: kind,
        reason: if reasons.is_empty() { "no policy matched".into() } else { reasons.join("; ") },
        rule_ids,
        flags,
    }
}

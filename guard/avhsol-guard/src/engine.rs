//! The decision engine behind `POST /v1/guard/tool`.
//!
//! Key idea (carried over from TRIVEKTRA): the verdict never depends on what the model says.
//! It depends on provenance (was untrusted content in context?) and on the user's own words
//! (did the *user* ask for this destination?).
use crate::detect::{find_secrets, scan_text};
use crate::policy::Policy;
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

/// Shell commands that open a network connection or ship data out.
static NET_CMD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(curl|wget|nc|ncat|netcat|socat|telnet|scp|sftp|rsync|ssh|ftp|tftp)\b|https?://|/dev/(tcp|udp)/|\b(requests|urllib|urlopen|http\.client|socket)\b").unwrap()
});
static URL_HOST: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(?:https?|ftp)://([a-z0-9._\-\[\]:]+)").unwrap());
static DESTRUCTIVE_CMD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive)\b|\bmkfs\b|\bdd\s+[^|;]*of=|:\(\)\s*\{|\bchmod\s+-R\s+[0-7]*7[0-7]*\s+/|>\s*/dev/sd|\bshred\b|\bgit\s+push\s+[^|;]*--force").unwrap()
});

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

/// The shell command text of a tool call, whatever the agent calls its argument
/// (`command`, `cmd`, `script`) and whether it is a string or an argv array (Codex-style).
pub fn command_text(args: &Value) -> String {
    for k in ["command", "cmd", "script", "code"] {
        match args.get(k) {
            Some(Value::String(s)) => return s.clone(),
            Some(Value::Array(a)) => return a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "),
            _ => {}
        }
    }
    String::new()
}

/// Maps the many names coding agents give their shell tool onto the policy's canonical "bash".
pub fn canonical_tool(name: &str) -> String {
    let l = name.to_lowercase();
    match l.as_str() {
        "bash" | "shell" | "sh" | "terminal" | "run_command" | "run_shell_command" | "execute_bash" | "exec_command" | "local_shell" => "bash".into(),
        _ => l,
    }
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
        "bash" => URL_HOST
            .captures_iter(&command_text(args))
            .map(|c| url_host(&format!("x://{}", &c[1])))
            .collect(),
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
    // bash is egress only when the command actually touches the network.
    let is_egress = policy.egress_tools.iter().any(|t| t == &req.tool)
        && (req.tool != "bash" || NET_CMD.is_match(&command_text(&req.args)));
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

    // D6: a context that has read untrusted content must not reach for protected files.
    if policy.enabled("D6", off) && !req.untrusted_sources.is_empty() && !policy.protected_paths.is_empty() {
        // Any tool (read, edit, bash, cat...) that names a protected path is covered.
        let touched = all_args_text(&req.args);
        let user = req.user_turns.join("\n").to_lowercase();
        for p in &policy.protected_paths {
            if touched.to_lowercase().contains(&p.to_lowercase()) && !user.contains(&p.to_lowercase()) {
                deny("D6", format!("tool '{}' touches protected path '{p}' after untrusted content, and the user never asked for it", req.tool), &mut rule_ids, &mut reasons, &mut kind);
                break;
            }
        }
    }

    // D7: destructive tools (and destructive shell commands) need a human.
    let destructive_cmd = req.tool == "bash" && DESTRUCTIVE_CMD.is_match(&command_text(&req.args));
    if policy.enabled("D7", off) && (destructive_cmd || policy.destructive_tools.iter().any(|t| t == &req.tool)) {
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

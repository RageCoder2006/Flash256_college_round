use abguard_core::{Decision, DecisionKind, GuardRequest, Policy};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Off,
    Monitor,
    Enforce,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "off" => Some(Mode::Off),
            "monitor" => Some(Mode::Monitor),
            "enforce" => Some(Mode::Enforce),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Monitor => "monitor",
            Mode::Enforce => "enforce",
        }
    }
    fn to_u8(self) -> u8 {
        self as u8
    }
    fn from_u8(v: u8) -> Mode {
        match v {
            0 => Mode::Off,
            1 => Mode::Monitor,
            _ => Mode::Enforce,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct Event {
    pub id: u64,
    pub ts_ms: u64,
    pub episode_id: String,
    pub tool: String,
    pub decision: DecisionKind,
    pub rule_ids: Vec<String>,
    pub reason: String,
    pub micros: u64,
}

#[derive(Default)]
struct Counters {
    allow: u64,
    deny: u64,
    approve: u64,
    by_rule: BTreeMap<String, u64>,
    decision_micros: Vec<u64>,
    proxy_micros: Vec<u64>,
    hidden_removed: u64,
    fenced_results: u64,
}

pub struct Shared {
    pub policy: RwLock<Policy>,
    mode: AtomicU8,
    pub upstream: String,
    pub http: reqwest::Client,
    next_id: AtomicU64,
    events: Mutex<VecDeque<Event>>,
    c: Mutex<Counters>,
}

const MAX_EVENTS: usize = 5000;
const MAX_SAMPLES: usize = 50_000;

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn pct(v: &[u64], p: f64) -> u64 {
    if v.is_empty() {
        return 0;
    }
    let mut s = v.to_vec();
    s.sort_unstable();
    s[(((s.len() - 1) as f64) * p).round() as usize]
}

impl Shared {
    pub fn new(policy: Policy, mode: Mode, upstream: String) -> Shared {
        Shared {
            policy: RwLock::new(policy),
            mode: AtomicU8::new(mode.to_u8()),
            upstream,
            http: reqwest::Client::new(),
            next_id: AtomicU64::new(1),
            events: Mutex::new(VecDeque::new()),
            c: Mutex::new(Counters::default()),
        }
    }
    pub fn mode(&self) -> Mode {
        Mode::from_u8(self.mode.load(Ordering::Relaxed))
    }
    pub fn set_mode(&self, m: Mode) {
        self.mode.store(m.to_u8(), Ordering::Relaxed)
    }

    pub fn record_decision(&self, req: &GuardRequest, d: &Decision, micros: u64) {
        let ev = Event {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            ts_ms: now_ms(),
            episode_id: req.episode_id.clone(),
            tool: req.tool.clone(),
            decision: d.decision,
            rule_ids: d.rule_ids.clone(),
            reason: d.reason.clone(),
            micros,
        };
        {
            let mut q = self.events.lock().unwrap();
            if q.len() >= MAX_EVENTS {
                q.pop_front();
            }
            q.push_back(ev);
        }
        let mut c = self.c.lock().unwrap();
        match d.decision {
            DecisionKind::Allow => c.allow += 1,
            DecisionKind::Deny => c.deny += 1,
            DecisionKind::Approve => c.approve += 1,
        }
        for r in &d.rule_ids {
            *c.by_rule.entry(r.clone()).or_default() += 1;
        }
        if c.decision_micros.len() < MAX_SAMPLES {
            c.decision_micros.push(micros);
        }
    }

    pub fn record_proxy_overhead(&self, micros: u64) {
        let mut c = self.c.lock().unwrap();
        if c.proxy_micros.len() < MAX_SAMPLES {
            c.proxy_micros.push(micros);
        }
    }

    pub fn note_sanitized(&self, hidden_removed: usize, fenced: bool) {
        let mut c = self.c.lock().unwrap();
        c.hidden_removed += hidden_removed as u64;
        if fenced {
            c.fenced_results += 1;
        }
    }

    pub fn events_since(&self, since: u64) -> Vec<Event> {
        self.events.lock().unwrap().iter().filter(|e| e.id > since).cloned().collect()
    }

    pub fn reset_metrics(&self) {
        *self.c.lock().unwrap() = Counters::default();
        self.events.lock().unwrap().clear();
    }

    pub fn metrics_json(&self) -> Value {
        let c = self.c.lock().unwrap();
        json!({
            "mode": self.mode().as_str(),
            "decisions": {"allow": c.allow, "deny": c.deny, "approve": c.approve},
            "by_rule": c.by_rule,
            "decision_latency_us": {"p50": pct(&c.decision_micros, 0.5), "p99": pct(&c.decision_micros, 0.99), "n": c.decision_micros.len()},
            "upstream_wait_us": {"p50": pct(&c.proxy_micros, 0.5), "p99": pct(&c.proxy_micros, 0.99), "n": c.proxy_micros.len()},
            "sanitized": {"hidden_chars_removed": c.hidden_removed, "fenced_tool_results": c.fenced_results},
        })
    }
}

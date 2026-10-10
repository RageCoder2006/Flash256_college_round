//! Content detectors. Ported from TRIVEKTRA `agent/internal/detect/contentscan.go`
//! (same code-point ranges and patterns) so both stay aligned with
//! `testdata/hidden_unicode_vectors.json`.
use once_cell::sync::Lazy;
use regex::Regex;

pub const FLAG_HIDDEN_UNICODE: &str = "hidden_unicode";
pub const FLAG_INSTRUCTION_OVERRIDE: &str = "instruction_override";
pub const FLAG_EXFIL_DIRECTIVE: &str = "exfil_directive";
pub const FLAG_FETCH_EXECUTE: &str = "fetch_execute";

/// Code points that render as nothing (or reorder text) but are read by a model.
pub fn hidden_rune(c: char) -> bool {
    matches!(c as u32,
        0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x2069 | 0xFEFF | 0xE0000..=0xE007F)
}

static OVERRIDE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|the)\b[^.\n]{0,40}\b(instructions?|rules?|prompts?|guidelines?)\b|\byou are now\b|\bnew (system )?instructions?\s*:|\bdo not (tell|inform|mention|reveal)[^.\n]{0,30}\b(user|human|developer)\b|\bwithout (telling|informing|notifying) (the )?(user|human|developer)\b").unwrap()
});
static EXFIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\b(curl|wget|nc|ncat|scp|https?://|post|upload|send|exfiltrat\w*)\b[^\n]{0,120}\b(\.env|\benv(ironment)?\b|secrets?|credentials?|tokens?|api[_ -]?keys?|ssh|id_rsa|\.aws|private key)\b)|(\b(secrets?|credentials?|tokens?|api[_ -]?keys?|\.env|ssh keys?)\b[^\n]{0,120}\b(curl|wget|to (the )?(url|server|endpoint|http)|https?://)\b)").unwrap()
});
static FETCH_EXEC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)((curl|wget)[^\n|]{0,160}\|\s*(ba)?sh\b)|(base64\s+(-d|--decode)[^\n]{0,80}\|\s*(ba)?sh\b)").unwrap()
});
/// Authority/impersonation and fence-forging markers (AgentBreak additions).
static SPOOF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\[\s*system( notice| message)?\b|</?\s*(system|untrusted-observed-data)\b|\bpre-?approved by\b|\bin maintenance mode\b").unwrap()
});
pub const FLAG_SPOOF: &str = "authority_spoof";

/// Returns the sorted, de-duplicated flags found in `text`.
pub fn scan_text(text: &str) -> Vec<&'static str> {
    let t = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = Vec::new();
    if t.chars().any(hidden_rune) {
        out.push(FLAG_HIDDEN_UNICODE);
    }
    if OVERRIDE_RE.is_match(t) {
        out.push(FLAG_INSTRUCTION_OVERRIDE);
    }
    if EXFIL_RE.is_match(t) {
        out.push(FLAG_EXFIL_DIRECTIVE);
    }
    if FETCH_EXEC_RE.is_match(t) {
        out.push(FLAG_FETCH_EXECUTE);
    }
    if SPOOF_RE.is_match(t) {
        out.push(FLAG_SPOOF);
    }
    out.sort_unstable();
    out
}

/// Secret-looking material. Used to refuse it in outbound arguments.
static SECRET_RES: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    let mk = |n, p: &str| (n, Regex::new(p).unwrap());
    vec![
        mk("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
        mk("github_token", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        mk("hf_token", r"\bhf_[A-Za-z0-9]{12,}\b"),
        mk("slack_token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        mk("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        mk("private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        mk("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
    ]
});

pub fn find_secrets(text: &str) -> Vec<&'static str> {
    SECRET_RES.iter().filter(|(_, re)| re.is_match(text)).map(|(n, _)| *n).collect()
}

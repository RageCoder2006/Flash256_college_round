use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capability {
    #[serde(default)]
    pub allowed_recipient_domains: Vec<String>,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Defenses switched on. IDs: D1 fence untrusted tool results, D2 strip hidden text / scan args, D3 capability, D4 taint egress, D5 secret egress, D7 approval gate.
    #[serde(default = "default_defenses")]
    pub defenses: Vec<String>,
    /// Tools that move data out of the system.
    #[serde(default = "default_egress")]
    pub egress_tools: Vec<String>,
    /// Tools that need a human to approve (no human in the loop => deny).
    #[serde(default)]
    pub destructive_tools: Vec<String>,
    /// Tools whose results carry content from outside the trust boundary (fenced/stripped on the wire).
    #[serde(default = "default_untrusted_tools")]
    pub untrusted_tools: Vec<String>,
    #[serde(default)]
    pub capabilities: BTreeMap<String, Capability>,
}

fn default_defenses() -> Vec<String> {
    ["D1", "D2", "D3", "D4", "D5", "D7"].iter().map(|s| s.to_string()).collect()
}
fn default_untrusted_tools() -> Vec<String> {
    ["read_document", "http_fetch", "memory_read"].iter().map(|s| s.to_string()).collect()
}
fn default_egress() -> Vec<String> {
    ["send_email", "http_fetch", "bash"].iter().map(|s| s.to_string()).collect()
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            defenses: default_defenses(),
            egress_tools: default_egress(),
            destructive_tools: vec![],
            untrusted_tools: default_untrusted_tools(),
            capabilities: BTreeMap::new(),
        }
    }
}

impl Policy {
    pub fn from_yaml(s: &str) -> Result<Policy, serde_yaml::Error> {
        serde_yaml::from_str(s)
    }
    pub fn enabled(&self, id: &str, off: &[String]) -> bool {
        self.defenses.iter().any(|d| d == id) && !off.iter().any(|d| d == id)
    }
    /// Stable hash of the policy for trace reproducibility.
    pub fn fingerprint(&self) -> String {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        serde_json::to_string(self).unwrap_or_default().hash(&mut h);
        format!("{:016x}", h.finish())
    }
}

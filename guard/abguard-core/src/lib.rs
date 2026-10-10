//! abguard-core: deterministic guard logic. Nothing here consults an LLM.
pub mod detect;
pub mod engine;
pub mod policy;
pub mod sanitize;

pub use engine::{decide, Decision, DecisionKind, GuardRequest};
pub use policy::Policy;

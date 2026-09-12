//! A host policy approval pins the complete artifact and runtime bundle.
//! Component closure digests remain cache hints; they are not approvals.

use crate::{check_ui_l0, Level};
use serde_json::{json, Value};

const POLICY: &str = "splash-ui-policy-v1:checked-L0-L1:runtime-origins:complete-tree";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactApproval {
    source: String,
    artifact: String,
    level: Level,
}

fn digest(parts: &[&str]) -> String {
    let mut hash = blake3::Hasher::new();
    for part in parts {
        hash.update(&(part.len() as u64).to_le_bytes());
        hash.update(part.as_bytes());
    }
    hash.finalize().to_hex().to_string()
}

impl ArtifactApproval {
    pub fn source_key(source: &str) -> String {
        digest(&["splash-source-v1", source.trim()])
    }

    /// The trusted host supplies a digest of its implementation, dependencies,
    /// capability bindings, and build configuration, plus the assembled kit.
    pub fn admit(source: &str, runtime: &str, kit: &str) -> Result<Self, String> {
        if runtime.is_empty() || kit.is_empty() {
            return Err("empty runtime approval bundle".into());
        }
        let report = check_ui_l0(source);
        if !report.valid || report.level == Level::L2 {
            return Err("card is outside the installed L0/L1 policy".into());
        }
        let source = Self::source_key(source);
        let artifact = digest(&[
            POLICY,
            &source,
            &format!("{:?}", report.level),
            runtime,
            kit,
            include_str!("lib.rs"),
            include_str!("value_origin.rs"),
            include_str!("approval.rs"),
        ]);
        Ok(Self {
            source,
            artifact,
            level: report.level,
        })
    }

    pub fn verify(&self, source: &str, runtime: &str, kit: &str) -> Result<(), String> {
        if *self != Self::admit(source, runtime, kit)? {
            return Err(
                "card approval does not match its source or runtime bundle; reapproval required"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn to_json(&self) -> Value {
        json!({"version":1,"source":self.source,"artifact":self.artifact,"level":format!("{:?}",self.level)})
    }

    pub fn from_json(value: &Value) -> Result<Self, String> {
        let parse = || {
            if value.get("version")?.as_u64()? != 1 {
                return None;
            }
            let level = match value.get("level")?.as_str()? {
                "L0" => Level::L0,
                "L1" => Level::L1,
                _ => return None,
            };
            let hash = |name| {
                let s = value.get(name)?.as_str()?;
                (s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
                .then(|| s.to_string())
            };
            Some(Self {
                source: hash("source")?,
                artifact: hash("artifact")?,
                level,
            })
        };
        parse().ok_or_else(|| "invalid stored card approval".into())
    }
}

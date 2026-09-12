//! Runtime origins are supplied by the host and propagated by the realizer.
//! No spelling in a card or JSON event envelope can grant an origin.

use crate::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ValueOrigin {
    #[default]
    Authored,
    Vocabulary,
    Source,
    UserInput,
    Host,
    Derived,
    Unknown,
}

impl ValueOrigin {
    pub fn permits_data(self) -> bool {
        matches!(
            self,
            Self::Vocabulary | Self::Source | Self::UserInput | Self::Host | Self::Derived
        )
    }

    fn combine(self, other: Self) -> Self {
        if self == Self::Unknown || other == Self::Unknown {
            Self::Unknown
        } else if self == other {
            self
        } else if self.permits_data() || other.permits_data() {
            Self::Derived
        } else {
            Self::Authored
        }
    }
}

impl ValueScope<'_> {
    pub(super) fn path_origin(&self, path: &str, card: &Card) -> ValueOrigin {
        let root = path.split('.').next().unwrap_or(path);
        if let Some((_, _, _, _, origin)) = self.frames.iter().rev().find(|(n, ..)| n == root) {
            return *origin;
        }
        if let Some(name) = path.strip_prefix("copy.") {
            return match self
                .copies
                .iter()
                .find(|c| c.name == name)
                .map(|c| c.provenance)
            {
                Some(Provenance::Vocabulary) => ValueOrigin::Vocabulary,
                // Copy class is authored metadata, not evidence of a native input.
                _ => ValueOrigin::Authored,
            };
        }
        if card
            .sources
            .iter()
            .any(|s| path == s.name || path.starts_with(&format!("{}.", s.name)))
        {
            ValueOrigin::Source
        } else {
            ValueOrigin::Unknown
        }
    }

    pub(super) fn operand_origin(&self, operand: &Operand, card: &Card) -> ValueOrigin {
        match operand {
            Operand::Path(p) => self.path_origin(p, card),
            Operand::Expr { lhs, rhs, .. } => self
                .operand_origin(lhs, card)
                .combine(self.operand_origin(rhs, card)),
            Operand::Predicate { path, rhs, .. } => self
                .path_origin(path, card)
                .combine(self.operand_origin(rhs, card)),
            Operand::Token(_) => ValueOrigin::Vocabulary,
            _ => ValueOrigin::Authored,
        }
    }
}

pub(super) fn initial_origin(state: &StateDecl, card: &Card) -> ValueOrigin {
    if state.initial.is_none() && state.initial_path.is_some() {
        ValueScope {
            frames: Vec::new(),
            data: &serde_json::Value::Null,
            copies: &card.copies,
        }
        .path_origin(state.initial_path.as_ref().unwrap(), card)
    } else if matches!(state.shape, Shape::Bool | Shape::Enum(_)) {
        ValueOrigin::Vocabulary
    } else {
        ValueOrigin::Authored
    }
}

pub(super) fn card_state_origin(
    state: &StateDecl,
    store: Option<&InstanceStore>,
    data: &serde_json::Value,
    card: &Card,
) -> ValueOrigin {
    store
        .and_then(|s| s.origin(CARD_STATE_KEY, &state.path))
        .unwrap_or_else(|| {
            if data.get(&state.path).is_some() {
                ValueOrigin::Host
            } else if state.initial.is_none()
                && state
                    .initial_path
                    .as_ref()
                    .is_some_and(|p| data_path(data, p).is_none())
            {
                ValueOrigin::Unknown
            } else {
                initial_origin(state, card)
            }
        })
}

/// Infer an event's payload origin from the realized control, never its JSON.
/// Call only for events delivered by the mounted native widget tree.
pub fn event_payload_origin(root: &UiNode, key: &str, event: &str) -> Option<ValueOrigin> {
    if root.key == key {
        let bound = root.args.iter().find(|(name, value)| {
            name.starts_with("on_") && matches!(value, NodeValue::Event(e) if e == event)
        })?;
        if root.kind == "Field" && matches!(bound.0.as_str(), "on_commit" | "on_change") {
            return Some(ValueOrigin::UserInput);
        }
        return Some(
            root.origins
                .iter()
                .find(|(n, _)| n == "value")
                .map(|(_, o)| *o)
                .unwrap_or(ValueOrigin::Authored),
        );
    }
    root.children
        .iter()
        .find_map(|n| event_payload_origin(n, key, event))
}

pub(super) fn needs_data_origin(kind: &str, argument: &str, value: &NodeValue) -> bool {
    // A Field's initial text and placeholder are editable interface defaults.
    if kind == "Field" {
        return false;
    }
    let slot = catalog::lookup(kind).and_then(|args| args.iter().find(|(n, _)| *n == argument));
    slot.is_some_and(|(_, k)| matches!(k, catalog::ArgKind::Data))
        || (argument == "text" && matches!(value, NodeValue::Number(_)))
}

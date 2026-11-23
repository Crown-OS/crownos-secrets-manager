use serde::{Deserialize, Serialize};

/// What happened when an agent asked to use a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UseOutcome {
    Done,
    /// The binding of the secret does not allow this agent or this target.
    Denied,
    /// The binding requires a password field and the focused field is not one.
    NotPasswordField,
    /// The page origin does not match the binding.
    OriginMismatch,
    RateLimited,
    Locked,
    /// No secret has this name.
    Unknown,
    /// The binding asks for a confirmation on screen, which this release cannot show yet. Only
    /// `confirm: Some(Never)` (or a default of `Never`) allows a use now.
    NeedsConfirmation,
    /// The focus left the target window before the compositor typed.
    FocusChanged,
    /// The user or the compositor stopped the typing.
    Cancelled,
}

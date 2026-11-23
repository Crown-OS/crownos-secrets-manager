//! The shared vocabulary of the CrownOS secrets manager.
//!
//! Agents name a secret by its [`SecretName`] and never see its value. This crate holds the types
//! that every other crate uses, the `secrets.ron` schema (which never holds a value), and the
//! [`Scrubber`] that removes a value and its common encodings from text before a model can read it.

pub mod binding;
pub mod config;
mod error;
mod kind;
mod name;
mod outcome;
pub mod scrub;
mod util;

pub use binding::{Binding, Confirm, HttpBinding, Target};
pub use config::SecretsConfig;
pub use error::CoreError;
pub use kind::SecretKind;
pub use name::SecretName;
pub use outcome::UseOutcome;
pub use scrub::{ScrubStream, Scrubber};

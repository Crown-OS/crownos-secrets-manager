use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::{HttpBinding, Scrubber, SecretName};

use crate::util::token::same_token;

/// A secret that a session may put into requests.
pub struct SessionSecret {
    pub name: SecretName,
    pub value: SecretSlice<u8>,
    pub http: Vec<HttpBinding>,
}

impl std::fmt::Debug for SessionSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionSecret")
            .field("name", &self.name)
            .field("http", &self.http)
            .finish_non_exhaustive()
    }
}

impl SessionSecret {
    pub(crate) fn binding_for(
        &self,
        authority: &str,
        method: &str,
        path: &str,
    ) -> Option<&HttpBinding> {
        self.http
            .iter()
            .find(|binding| binding.matches_request(authority, method, path))
    }
}

pub(crate) struct Session {
    pub(crate) id: u64,
    pub(crate) actor: String,
    pub(crate) secrets: Vec<SessionSecret>,
    pub(crate) scrubber: Arc<Scrubber>,
    expires_at: Instant,
}

impl Session {
    pub(crate) fn new(
        id: u64,
        actor: String,
        secrets: Vec<SessionSecret>,
        expires_at: Instant,
    ) -> Self {
        let mut scrubber = Scrubber::new();
        for secret in &secrets {
            scrubber.add_secret(&secret.name, secret.value.expose_secret());
        }
        Self {
            id,
            actor,
            secrets,
            scrubber: Arc::new(scrubber),
            expires_at,
        }
    }

    pub(crate) fn allows_authority(&self, authority: &str) -> bool {
        self.secrets.iter().any(|secret| {
            secret
                .http
                .iter()
                .any(|binding| binding.matches_authority(authority))
        })
    }
}

/// Open sessions by token. A lookup never returns an expired session.
#[derive(Default)]
pub(crate) struct Sessions(Mutex<HashMap<String, Arc<Session>>>);

impl Sessions {
    pub(crate) fn insert(&self, token: String, session: Session) {
        if let Ok(mut sessions) = self.0.lock() {
            sessions.insert(token, Arc::new(session));
        }
    }

    pub(crate) fn find(&self, token: &str, now: Instant) -> Option<Arc<Session>> {
        let sessions = self.0.lock().ok()?;
        sessions
            .iter()
            .find(|(stored, session)| same_token(stored, token) && now < session.expires_at)
            .map(|(_, session)| Arc::clone(session))
    }

    pub(crate) fn revoke(&self, id: u64, actor: &str) -> bool {
        let Ok(mut sessions) = self.0.lock() else {
            return false;
        };
        let before = sessions.len();
        sessions.retain(|_, session| !(session.id == id && session.actor == actor));
        sessions.len() != before
    }

    pub(crate) fn revoke_all(&self) {
        if let Ok(mut sessions) = self.0.lock() {
            sessions.clear();
        }
    }

    pub(crate) fn forget_expired(&self, now: Instant) {
        if let Ok(mut sessions) = self.0.lock() {
            sessions.retain(|_, session| now < session.expires_at);
        }
    }
}

//! Which uses need the dialog, and what the answers allow afterwards. All of it lives in memory.

use std::time::{Duration, Instant};

use secrets_core::{Confirm, SecretName, TemplateName};

use super::SecretsService;
use crate::Caller;
use crate::confirmation::{DialogRequest, Verdict};

/// After a deny or no answer, the same agent gets no new dialog for this long.
const DENY_COOL_DOWN: Duration = Duration::from_secs(60);

/// The answer for the one request that the server dispatches again after the dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decision {
    app_key: String,
    names: Vec<SecretName>,
    verdict: Verdict,
}

/// What a use needs before it can go on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmation {
    /// No dialog: the rules say never, an earlier answer covers it, or another check refuses.
    NotNeeded,
    Ask(DialogRequest),
    /// A dialog for this agent is open already, or it was denied a moment ago: refuse.
    Refuse,
}

/// One question to [`SecretsService::confirm_check`].
#[derive(Clone, Copy)]
pub(crate) struct ConfirmQuery<'query> {
    pub(crate) caller: &'query Caller,
    pub(crate) app_key: &'query str,
    pub(crate) names: &'query [SecretName],
    pub(crate) confirms: &'query [Confirm],
    pub(crate) target: &'query str,
    pub(crate) now: Instant,
    pub(crate) consume: bool,
}

/// What the confirmation part of a check says.
pub(crate) enum ConfirmCheck {
    Passed,
    Denied,
    Unreachable,
    /// A dialog must run first.
    Ask(DialogRequest),
}

impl SecretsService {
    /// Whether a use of `names` by `caller` at `target` needs the dialog first. It consumes no
    /// rate limit and writes no audit line; the dispatch after the dialog does that.
    pub fn confirmation_for(
        &mut self,
        caller: &Caller,
        names: &[SecretName],
        target: &str,
        now: Instant,
    ) -> Confirmation {
        self.lock_if_expired(now);
        let Some(app_key) = caller.app_key_text() else {
            return Confirmation::NotNeeded;
        };
        let Ok(contents) = self.vault.contents(now) else {
            return Confirmation::NotNeeded;
        };
        let rules = contents.rules();
        let mut confirms = Vec::with_capacity(names.len());
        for name in names {
            match rules.secrets.get(name) {
                Some(entry) if entry.binding.allows_agent(&app_key) && contents.contains(name) => {
                    confirms.push(entry.binding.confirm_or(rules.settings.default_confirm));
                }
                _ => return Confirmation::NotNeeded,
            }
        }
        if names.is_empty() {
            return Confirmation::NotNeeded;
        }
        let query = ConfirmQuery {
            caller,
            app_key: &app_key,
            names,
            confirms: &confirms,
            target,
            now,
            consume: false,
        };
        match self.confirm_check(&query) {
            ConfirmCheck::Ask(request) if self.open_dialogs.contains(&app_key) => {
                drop(request);
                Confirmation::Refuse
            }
            ConfirmCheck::Ask(request) => Confirmation::Ask(request),
            ConfirmCheck::Denied => Confirmation::Refuse,
            ConfirmCheck::Passed | ConfirmCheck::Unreachable => Confirmation::NotNeeded,
        }
    }

    /// The confirmation part of a check. With `consume`, a decision for this request is used
    /// up.
    pub(crate) fn confirm_check(&mut self, query: &ConfirmQuery<'_>) -> ConfirmCheck {
        let ConfirmQuery {
            caller,
            app_key,
            names,
            confirms,
            target,
            now,
            consume,
        } = *query;
        if confirms.iter().all(|confirm| *confirm == Confirm::Never) {
            return ConfirmCheck::Passed;
        }
        let decided = self
            .decision
            .as_ref()
            .filter(|decision| decision.app_key == app_key && decision.names == names)
            .map(|decision| decision.verdict);
        if let Some(verdict) = decided {
            if consume {
                self.decision = None;
            }
            return match verdict {
                Verdict::Granted => ConfirmCheck::Passed,
                Verdict::Denied => ConfirmCheck::Denied,
                Verdict::Unreachable => ConfirmCheck::Unreachable,
            };
        }
        if self
            .deny_cool_downs
            .get(app_key)
            .is_some_and(|until| now < *until)
        {
            return ConfirmCheck::Denied;
        }
        let covered = names
            .iter()
            .zip(confirms)
            .all(|(name, confirm)| match confirm {
                Confirm::Never => true,
                Confirm::PerSession(_) => self
                    .session_approvals
                    .get(&(app_key.to_owned(), name.clone()))
                    .is_some_and(|until| now < *until),
                Confirm::EveryUse => false,
            });
        if covered {
            return ConfirmCheck::Passed;
        }
        let session_minutes = confirms
            .iter()
            .map(|confirm| match confirm {
                Confirm::PerSession(minutes) => Some(*minutes),
                Confirm::Never => Some(u32::MAX),
                Confirm::EveryUse => None,
            })
            .try_fold(u32::MAX, |shortest, minutes| {
                minutes.map(|minutes| shortest.min(minutes))
            })
            .filter(|minutes| *minutes != u32::MAX);
        ConfirmCheck::Ask(DialogRequest {
            app_key: app_key.to_owned(),
            agent: caller.display_name(),
            names: names.to_vec(),
            target: target.to_owned(),
            session_minutes,
        })
    }

    /// The secrets in the environment of a template, for the dialog.
    pub(crate) fn template_secret_names(
        &mut self,
        template: &TemplateName,
        now: Instant,
    ) -> Option<Vec<SecretName>> {
        let contents = self.vault.contents(now).ok()?;
        let template = contents.rules().run_templates.get(template)?;
        Some(template.environment.values().cloned().collect())
    }

    /// The bound hosts of `names`, for the dialog.
    pub(crate) fn proxy_hosts(&mut self, names: &[SecretName], now: Instant) -> String {
        let Ok(contents) = self.vault.contents(now) else {
            return String::new();
        };
        let hosts: std::collections::BTreeSet<&str> = names
            .iter()
            .filter_map(|name| contents.rules().secrets.get(name))
            .flat_map(|entry| entry.binding.http.iter().map(|http| http.host.as_str()))
            .collect();
        hosts.into_iter().collect::<Vec<_>>().join(", ")
    }

    pub(crate) fn dialog_opened(&mut self, request: &DialogRequest) {
        self.open_dialogs.insert(request.app_key.clone());
    }

    /// Records the answer and keeps it for the one dispatch that follows.
    pub(crate) fn dialog_answered(
        &mut self,
        request: &DialogRequest,
        verdict: Verdict,
        now: Instant,
    ) {
        self.open_dialogs.remove(&request.app_key);
        match verdict {
            Verdict::Granted => {
                if let Some(minutes) = request.session_minutes {
                    let until = now + Duration::from_secs(u64::from(minutes) * 60);
                    for name in &request.names {
                        self.session_approvals
                            .insert((request.app_key.clone(), name.clone()), until);
                    }
                }
            }
            Verdict::Denied => {
                self.deny_cool_downs
                    .insert(request.app_key.clone(), now + DENY_COOL_DOWN);
            }
            Verdict::Unreachable => {}
        }
        self.decision = Some(Decision {
            app_key: request.app_key.clone(),
            names: request.names.clone(),
            verdict,
        });
    }

    /// Drops a decision that its dispatch did not use, for example when the caller left.
    pub(crate) fn forget_decision(&mut self) {
        self.decision = None;
    }

    /// Answers a use at once with a deny, through the normal dispatch.
    pub(crate) fn decide_denied(&mut self, caller: &Caller, names: &[SecretName]) {
        if let Some(app_key) = caller.app_key_text() {
            self.decision = Some(Decision {
                app_key,
                names: names.to_vec(),
                verdict: Verdict::Denied,
            });
        }
    }
}

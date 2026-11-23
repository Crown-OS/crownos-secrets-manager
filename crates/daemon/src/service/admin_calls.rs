//! Calls that only the admin executables may make. Each one that changes the vault needs the
//! master password; none of them returns a value.

use std::time::Instant;

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::{
    Binding, RunTemplate, SecretEntry, SecretKind, SecretName, TemplateName, VaultSettings,
};
use secrets_protocol::transfer::TransferError;
use secrets_vault::OpenVault;

use super::{SecretsService, ServiceError};
use crate::{Caller, audit};

/// Reads a value or the master password from its pipe. It runs only after the admin check.
pub trait ReadSecret: FnOnce() -> Result<SecretSlice<u8>, TransferError> {}

impl<Read: FnOnce() -> Result<SecretSlice<u8>, TransferError>> ReadSecret for Read {}

impl SecretsService {
    /// Creates the vault.
    ///
    /// # Errors
    ///
    /// Fails for a caller that is not an admin, when a vault exists, or on a write error.
    pub fn init(
        &mut self,
        caller: &Caller,
        read_password: impl ReadSecret,
        now: Instant,
    ) -> Result<(), ServiceError> {
        let result = self.require_admin(caller).and_then(|()| {
            let password = read_password()?;
            Ok(self.vault.init(password.expose_secret(), now)?)
        });
        audit::admin_call(caller, "init", None, result_name(&result));
        result
    }

    /// # Errors
    ///
    /// Fails for a caller that is not an admin, a missing vault or a wrong password.
    pub fn unlock(
        &mut self,
        caller: &Caller,
        read_password: impl ReadSecret,
        now: Instant,
    ) -> Result<(), ServiceError> {
        let result = self.require_admin(caller).and_then(|()| {
            let password = read_password()?;
            Ok(self.vault.unlock(password.expose_secret(), now)?)
        });
        audit::admin_call(caller, "unlock", None, result_name(&result));
        result
    }

    /// # Errors
    ///
    /// Fails for a caller that is not an admin.
    pub fn lock(&mut self, caller: &Caller) -> Result<(), ServiceError> {
        let result = self.require_admin(caller).map(|()| {
            self.vault.lock();
            self.proxy = None;
        });
        audit::admin_call(caller, "lock", None, result_name(&result));
        result
    }

    /// Stores a value. A new secret gets an empty binding; a replaced one keeps its binding.
    ///
    /// # Errors
    ///
    /// Fails for a caller that is not an admin, a wrong password, or a read or write error.
    pub fn add(
        &mut self,
        caller: &Caller,
        name: &SecretName,
        kind: SecretKind,
        read_password: impl ReadSecret,
        read_value: impl ReadSecret,
        now: Instant,
    ) -> Result<(), ServiceError> {
        self.change_vault(caller, "add", Some(name), read_password, now, |vault| {
            let value = read_value()?;
            let binding = vault
                .rules()
                .secrets
                .get(name)
                .map(|entry| entry.binding.clone())
                .unwrap_or_default();
            Ok(vault.insert_secret(name.clone(), SecretEntry { kind, binding }, value)?)
        })?;
        self.pending_requests
            .retain(|request| request.name != *name);
        Ok(())
    }

    /// # Errors
    ///
    /// Fails for a caller that is not an admin, a wrong password, or a write error.
    pub fn remove(
        &mut self,
        caller: &Caller,
        name: &SecretName,
        read_password: impl ReadSecret,
        now: Instant,
    ) -> Result<bool, ServiceError> {
        let removed =
            self.change_vault(caller, "remove", Some(name), read_password, now, |vault| {
                Ok(vault.remove_secret(name)?)
            })?;
        self.last_used.remove(name);
        Ok(removed)
    }

    /// Replaces the rules of a secret.
    ///
    /// # Errors
    ///
    /// Fails for a caller that is not an admin, a wrong password, an unknown secret, an invalid
    /// binding, or a write error.
    pub fn bind(
        &mut self,
        caller: &Caller,
        name: &SecretName,
        binding: Binding,
        read_password: impl ReadSecret,
        now: Instant,
    ) -> Result<(), ServiceError> {
        self.change_vault(caller, "bind", Some(name), read_password, now, |vault| {
            binding.validate()?;
            if !vault.rules().secrets.contains_key(name) {
                return Err(ServiceError::UnknownSecret(name.clone()));
            }
            Ok(vault.change_rules(|rules| {
                if let Some(entry) = rules.secrets.get_mut(name) {
                    entry.binding = binding;
                }
            })?)
        })
    }

    /// Adds, replaces or, with `None`, removes a run template.
    ///
    /// # Errors
    ///
    /// Fails for a caller that is not an admin, a wrong password, an invalid template, or a
    /// write error.
    pub fn set_template(
        &mut self,
        caller: &Caller,
        name: &TemplateName,
        template: Option<RunTemplate>,
        read_password: impl ReadSecret,
        now: Instant,
    ) -> Result<(), ServiceError> {
        self.change_vault(caller, "set-template", None, read_password, now, |vault| {
            if let Some(template) = &template {
                template.validate()?;
            }
            Ok(vault.change_rules(|rules| match template {
                Some(template) => {
                    rules.run_templates.insert(name.clone(), template);
                }
                None => {
                    rules.run_templates.remove(name);
                }
            })?)
        })
    }

    /// Replaces the lock time, the default confirmation and the rate limits. A new lock time
    /// counts from the next unlock.
    ///
    /// # Errors
    ///
    /// Fails for a caller that is not an admin, a wrong password, or a write error.
    pub fn configure(
        &mut self,
        caller: &Caller,
        settings: VaultSettings,
        read_password: impl ReadSecret,
        now: Instant,
    ) -> Result<(), ServiceError> {
        self.change_vault(caller, "configure", None, read_password, now, |vault| {
            Ok(vault.change_rules(|rules| rules.settings = settings)?)
        })
    }

    /// The admin check, then the master password check, then `change`; one audit line. A
    /// change ends every proxy session, so no session keeps a binding that was just removed.
    pub(crate) fn change_vault<Changed>(
        &mut self,
        caller: &Caller,
        call: &str,
        name: Option<&SecretName>,
        read_password: impl ReadSecret,
        now: Instant,
        change: impl FnOnce(&mut OpenVault) -> Result<Changed, ServiceError>,
    ) -> Result<Changed, ServiceError> {
        let result = self.require_admin(caller).and_then(|()| {
            let password = read_password()?;
            let vault = self.vault.authorize(password.expose_secret(), now)?;
            change(vault)
        });
        if result.is_ok()
            && let Some(proxy) = &self.proxy
        {
            proxy.revoke_all();
        }
        audit::admin_call(caller, call, name, result_name(&result));
        result
    }

    fn require_admin(&self, caller: &Caller) -> Result<(), ServiceError> {
        if self.is_admin(caller) {
            Ok(())
        } else {
            Err(ServiceError::NotAdmin)
        }
    }
}

const fn result_name<T>(result: &Result<T, ServiceError>) -> &'static str {
    match result {
        Ok(_) => "done",
        Err(ServiceError::NotAdmin) => "not-admin",
        Err(ServiceError::Locked) => "locked",
        Err(ServiceError::UnknownSecret(_)) => "unknown",
        Err(ServiceError::Vault(_)) => "vault-error",
        Err(_) => "failed",
    }
}

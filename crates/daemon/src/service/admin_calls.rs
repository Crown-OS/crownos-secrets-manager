//! Calls that only the admin executables may make. They change the vault or the rules; none of
//! them returns a value.

use std::time::Instant;

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::config::SecretEntry;
use secrets_core::{Binding, SecretKind, SecretName};

use super::{SecretsService, ServiceError};
use crate::{Caller, ConfigStore, audit};

impl<Store: ConfigStore> SecretsService<Store> {
    /// Stores a value and names the secret in `secrets.ron`. A new secret gets an empty binding.
    ///
    /// # Errors
    ///
    /// Fails for a caller that is not an admin, a locked vault, or a write error.
    pub fn add(
        &mut self,
        caller: &Caller,
        name: &SecretName,
        kind: SecretKind,
        value: SecretSlice<u8>,
        now: Instant,
    ) -> Result<(), ServiceError> {
        let result = self.add_checked(caller, name, kind, value, now);
        audit::admin_call(caller, "add", Some(name), result_name(&result));
        result
    }

    fn add_checked(
        &mut self,
        caller: &Caller,
        name: &SecretName,
        kind: SecretKind,
        value: SecretSlice<u8>,
        now: Instant,
    ) -> Result<(), ServiceError> {
        self.require_admin(caller)?;
        if value.expose_secret().is_empty() {
            return Err(secrets_protocol::transfer::TransferError::Empty.into());
        }
        self.vault.contents_mut(now)?.insert(name.clone(), value)?;
        let entry = self
            .config
            .secrets
            .entry(name.clone())
            .or_insert_with(|| SecretEntry {
                kind,
                binding: Binding::default(),
            });
        entry.kind = kind;
        self.store.save(&self.config)?;
        self.pending_requests
            .retain(|request| request.name != *name);
        Ok(())
    }

    /// # Errors
    ///
    /// Fails for a caller that is not an admin, a locked vault, or a write error.
    pub fn remove(
        &mut self,
        caller: &Caller,
        name: &SecretName,
        now: Instant,
    ) -> Result<bool, ServiceError> {
        let result = self.remove_checked(caller, name, now);
        audit::admin_call(caller, "remove", Some(name), result_name(&result));
        result
    }

    fn remove_checked(
        &mut self,
        caller: &Caller,
        name: &SecretName,
        now: Instant,
    ) -> Result<bool, ServiceError> {
        self.require_admin(caller)?;
        let in_vault = self.vault.contents_mut(now)?.remove(name)?;
        let in_config = self.config.secrets.remove(name).is_some();
        if in_config {
            self.store.save(&self.config)?;
        }
        self.last_used.remove(name);
        Ok(in_vault || in_config)
    }

    /// Replaces the rules of a secret.
    ///
    /// # Errors
    ///
    /// Fails for a caller that is not an admin, a locked vault, an unknown secret, an invalid
    /// binding, or a write error.
    pub fn bind(
        &mut self,
        caller: &Caller,
        name: &SecretName,
        binding: Binding,
        now: Instant,
    ) -> Result<(), ServiceError> {
        let result = self.bind_checked(caller, name, binding, now);
        audit::admin_call(caller, "bind", Some(name), result_name(&result));
        result
    }

    fn bind_checked(
        &mut self,
        caller: &Caller,
        name: &SecretName,
        binding: Binding,
        now: Instant,
    ) -> Result<(), ServiceError> {
        self.require_admin(caller)?;
        self.vault.contents(now)?;
        binding.validate()?;
        let entry = self
            .config
            .secrets
            .get_mut(name)
            .ok_or_else(|| ServiceError::UnknownSecret(name.clone()))?;
        entry.binding = binding;
        self.store.save(&self.config)?;
        Ok(())
    }

    /// # Errors
    ///
    /// Fails for a caller that is not an admin.
    pub fn lock(&mut self, caller: &Caller) -> Result<(), ServiceError> {
        let result = self.require_admin(caller).map(|()| self.vault.lock());
        audit::admin_call(caller, "lock", None, result_name(&result));
        result
    }

    /// Unlocks the vault, or creates it with this password when no vault exists.
    ///
    /// # Errors
    ///
    /// Fails for a caller that is not an admin or a wrong password.
    pub fn unlock(
        &mut self,
        caller: &Caller,
        password: &SecretSlice<u8>,
        now: Instant,
    ) -> Result<(), ServiceError> {
        let result = self.unlock_checked(caller, password, now);
        audit::admin_call(caller, "unlock", None, result_name(&result));
        result
    }

    fn unlock_checked(
        &mut self,
        caller: &Caller,
        password: &SecretSlice<u8>,
        now: Instant,
    ) -> Result<(), ServiceError> {
        self.require_admin(caller)?;
        self.reload_config();
        self.vault.unlock(password.expose_secret(), now)?;
        Ok(())
    }

    fn require_admin(&mut self, caller: &Caller) -> Result<(), ServiceError> {
        self.reload_config();
        if caller.is_any_of(&self.config.admin_executables) {
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

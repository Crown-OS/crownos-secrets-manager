use secrets_core::{Binding, Confirm, Target};
use secrets_protocol::{SecretMeta, TemplateMeta, VaultStatus};

pub(crate) fn print_secrets(secrets: &[SecretMeta]) {
    if secrets.is_empty() {
        println!("No secrets. Add one with `crownos-secrets add <name> --kind <kind>`.");
        return;
    }
    for secret in secrets {
        println!("{}  ({})", secret.name, secret.kind);
        print_binding(&secret.binding);
    }
}

fn print_binding(binding: &Binding) {
    let agents = if binding.agents.is_empty() {
        "none".to_owned()
    } else {
        binding.agents.join(", ")
    };
    println!("    agents:  {agents}");
    for target in &binding.targets {
        match target {
            Target::AppId(pattern) => println!("    app id:  {pattern}"),
            Target::Origin(pattern) => println!("    origin:  {pattern}"),
        }
    }
    if binding.require_password_field {
        println!("    only into password fields");
    }
    match binding.confirm {
        Some(Confirm::EveryUse) => println!("    confirm: every use"),
        Some(Confirm::PerSession(minutes)) => println!("    confirm: once per {minutes} minutes"),
        Some(Confirm::Never) => println!("    confirm: never"),
        None => {}
    }
    for http in &binding.http {
        println!(
            "    http:    {} header {}: {}",
            http.host, http.header, http.format
        );
    }
}

pub(crate) fn print_templates(templates: &[TemplateMeta]) {
    if templates.is_empty() {
        println!(
            "No templates. Add one with `crownos-secrets template-set <name> ... -- <command>`."
        );
        return;
    }
    for TemplateMeta { name, template } in templates {
        println!("{name}: {}", template.command.join(" "));
        for (variable, secret) in &template.environment {
            println!("    env:     {variable} from {secret}");
        }
        let network = if template.network.is_empty() {
            "none".to_owned()
        } else {
            template.network.join(", ")
        };
        println!("    network: {network}");
        println!(
            "    cwd:     {}",
            if template.cwd_glob.is_empty() {
                "empty temporary directory"
            } else {
                &template.cwd_glob
            }
        );
    }
}

pub(crate) fn print_status(status: &VaultStatus) {
    let state = match (status.vault_exists, status.locks_in_seconds) {
        (false, _) => "no vault yet; `crownos-secrets init` creates one".to_owned(),
        (true, Some(seconds)) => format!("unlocked, locks in {} min", seconds.div_ceil(60)),
        (true, None) => "locked".to_owned(),
    };
    println!("vault:   {state}");
    for request in &status.pending_requests {
        println!(
            "request {}: {} wants `{}` ({}): {}",
            request.id.0,
            request.requested_by.escape_debug(),
            request.name,
            request.kind,
            request.purpose.escape_debug()
        );
    }
}

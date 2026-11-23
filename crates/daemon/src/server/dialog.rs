//! The consent dialog before a run or a proxy session, which the compositor shows. Typing has
//! no such dialog here: the compositor asks for each typing request itself.

use std::time::Instant;

use crownos_ipc::{Message, MethodMsg, PeerId};
use secrets_core::SecretName;
use secrets_protocol::secrets;
use tokio::sync::mpsc::UnboundedSender;

use super::Outgoing;
use crate::SecretsService;
use crate::confirmation::{DialogRequest, UseKind};

/// Opens the dialog in a task; the answer comes back as [`Outgoing::Answered`].
pub(super) fn ask_first(
    service: &mut SecretsService,
    peer: PeerId,
    message: Message,
    request: DialogRequest,
    outgoing: &UnboundedSender<Outgoing>,
) {
    service.dialog_opened(&request);
    let asker = service.confirmation_asker();
    let outgoing = outgoing.clone();
    let kind = if message.selector == <secrets::proxy_session as MethodMsg>::SELECTOR {
        UseKind::Proxy
    } else {
        UseKind::Run
    };
    tokio::spawn(async move {
        let verdict = asker.ask(kind, request.clone()).await;
        let _ = outgoing.send(Outgoing::Answered {
            peer,
            message,
            request,
            verdict,
        });
    });
}

/// The secrets that a request wants to use, and a text for the dialog, or `None` for a request
/// that uses no secret.
pub(super) fn use_request(
    service: &mut SecretsService,
    message: &Message,
) -> Option<(Vec<SecretName>, String)> {
    let payload = &message.payload;
    let decode_failed = |_| ();
    match message.selector {
        selector if selector == <secrets::run as MethodMsg>::SELECTOR => {
            let request: secrets::run = crownos_ipc::postcard::from_bytes(payload)
                .map_err(decode_failed)
                .ok()?;
            let names = service.template_secret_names(&request.template, Instant::now())?;
            Some((
                names,
                format!("the command template “{}”", request.template),
            ))
        }
        selector if selector == <secrets::proxy_session as MethodMsg>::SELECTOR => {
            let request: secrets::proxy_session = crownos_ipc::postcard::from_bytes(payload)
                .map_err(decode_failed)
                .ok()?;
            let hosts = service.proxy_hosts(&request.names, Instant::now());
            Some((request.names, format!("HTTPS requests to {hosts}")))
        }
        _ => None,
    }
}

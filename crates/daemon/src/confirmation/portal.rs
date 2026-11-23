//! The question through the desktop portal's Access dialog, the same one crownpositor and
//! crown-contextd ask with, in its dangerous style.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use zbus::Connection;
use zbus::zvariant::{ObjectPath, OwnedValue, Value};

use super::{ANSWER_TIME, ConfirmationAsker, DialogRequest, Verdict, VerdictFuture};

const BACKENDS: [&str; 2] = [
    "org.freedesktop.impl.portal.desktop.crownos",
    "org.freedesktop.impl.portal.desktop.gtk",
];
const PATH: &str = "/org/freedesktop/portal/desktop";
const INTERFACE: &str = "org.freedesktop.impl.portal.Access";
const SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
const GRANTED: u32 = 0;

#[derive(Debug, Default)]
pub struct PortalAsker;

impl ConfirmationAsker for PortalAsker {
    fn ask(&self, request: DialogRequest) -> VerdictFuture {
        Box::pin(async move {
            match tokio::time::timeout(ANSWER_TIME, ask_portal(&request)).await {
                Ok(Ok(true)) => Verdict::Granted,
                Ok(Ok(false)) | Err(_) => Verdict::Denied,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "no portal can ask the user");
                    Verdict::Unreachable
                }
            }
        })
    }
}

async fn ask_portal(request: &DialogRequest) -> Result<bool, String> {
    static NEXT_TICKET: AtomicU64 = AtomicU64::new(1);
    let ticket = NEXT_TICKET.fetch_add(1, Ordering::Relaxed);
    let connection = Connection::session()
        .await
        .map_err(|error| error.to_string())?;
    let handle = ObjectPath::try_from(format!("/org/crownos/secretsd/request/{ticket}"))
        .map_err(|error| error.to_string())?;
    let title = request.title();
    let body = request.body();
    let mut options: HashMap<&str, Value<'_>> = HashMap::new();
    options.insert("modal", true.into());
    options.insert("grant_label", "Allow".into());
    options.insert("deny_label", "Deny".into());
    options.insert("crownos-level", "dangerous".into());
    for backend in BACKENDS {
        let reply = connection
            .call_method(
                Some(backend),
                PATH,
                Some(INTERFACE),
                "AccessDialog",
                &(
                    &handle,
                    request.app_key.as_str(),
                    "",
                    title.as_str(),
                    "",
                    body.as_str(),
                    &options,
                ),
            )
            .await;
        match reply {
            Ok(reply) => {
                let (response, _results): (u32, HashMap<String, OwnedValue>) = reply
                    .body()
                    .deserialize()
                    .map_err(|error| error.to_string())?;
                return Ok(response == GRANTED);
            }
            Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == SERVICE_UNKNOWN => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("no portal backend offers an access dialog".to_owned())
}

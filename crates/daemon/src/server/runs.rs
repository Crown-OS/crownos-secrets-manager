use std::time::Instant;

use crownos_ipc::{Message, PeerId, RemoteError, Server};
use secrets_protocol::{RunReply, secrets};
use tokio::sync::mpsc::UnboundedSender;

use super::Outgoing;
use super::replies::{encoded, send_reply};
use crate::service::RunStart;
use crate::{Caller, SecretsService};

/// Checks a run at once; a run that passes goes to a task, which answers when it ends.
pub(super) fn start_run(
    service: &mut SecretsService,
    caller: &Caller,
    server: &mut Server,
    peer: PeerId,
    message: &Message,
    finished_runs: &UnboundedSender<Outgoing>,
) {
    let Ok(arguments) = crownos_ipc::postcard::from_bytes::<secrets::run>(&message.payload) else {
        server.drop_peer(peer);
        return;
    };
    let request = message.req_id;
    let started = service.prepare_run(
        caller,
        &arguments.template,
        &arguments.arguments,
        &arguments.cwd,
        Instant::now(),
    );
    match started {
        Ok(RunStart::Refused(reply)) => send_reply(server, peer, request, &Ok(reply)),
        Err(error) => send_reply::<RunReply>(server, peer, request, &Err(error.into())),
        Ok(RunStart::Ready(job)) => {
            let finished_runs = finished_runs.clone();
            tokio::spawn(async move {
                let reply = job.execute().await.map_err(RemoteError::from);
                let _ = finished_runs.send(Outgoing::Reply {
                    peer,
                    request,
                    reply: encoded(reply),
                });
            });
        }
    }
}

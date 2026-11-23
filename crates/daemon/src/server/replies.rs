use crownos_ipc::{PeerId, RemoteError, Server};

pub(super) fn send_encoded_reply(
    server: &mut Server,
    peer: PeerId,
    request: u32,
    reply: Result<Vec<u8>, RemoteError>,
) {
    let sent = match reply {
        Ok(payload) => server.reply(peer, request, &payload, Vec::new()),
        Err(error) => server.reply_err(peer, request, &error),
    };
    if let Err(error) = sent {
        tracing::debug!(%error, "cannot send a reply; the caller may have gone");
    }
}

/// The encoded form of a reply for [`Outgoing::Reply`].
pub(super) fn encoded<Reply: serde::Serialize>(
    reply: Result<Reply, RemoteError>,
) -> Result<Vec<u8>, RemoteError> {
    reply.and_then(|reply| {
        crownos_ipc::postcard::to_stdvec(&reply)
            .map_err(|_| RemoteError::handler("reply encoding failed"))
    })
}

pub(super) fn send_reply<Reply: serde::Serialize>(
    server: &mut Server,
    peer: PeerId,
    request: u32,
    reply: &Result<Reply, RemoteError>,
) {
    let sent = match reply {
        Ok(reply) => match crownos_ipc::postcard::to_stdvec(reply) {
            Ok(payload) => server.reply(peer, request, &payload, Vec::new()),
            Err(_) => server.reply_err(
                peer,
                request,
                &RemoteError::handler("reply encoding failed"),
            ),
        },
        Err(error) => server.reply_err(peer, request, error),
    };
    if let Err(error) = sent {
        tracing::debug!(%error, "cannot send a reply; the caller may have gone");
    }
}

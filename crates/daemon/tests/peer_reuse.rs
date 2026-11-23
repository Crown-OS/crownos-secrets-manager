//! A reply that a task sends after its caller left must not reach a new client in the same
//! connection slot. crownos-ipc tags each peer id with a generation; this test holds the daemon
//! to that.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Read as _;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use secrets_protocol::secrets;

fn accept_one(server: &mut crownos_ipc::Server) -> crownos_ipc::PeerId {
    for _ in 0..100 {
        if let Some(peer) = server.accept().unwrap() {
            return peer;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("no client connected");
}

#[test]
fn a_late_reply_does_not_reach_a_new_client_in_the_same_slot() {
    let directory = tempfile::tempdir().unwrap();
    let mut server = crownos_secretsd::server::bind_socket(Some(directory.path())).unwrap();
    let socket = directory.path().join(format!("{}.sock", secrets::SERVICE));

    let first = UnixStream::connect(&socket).unwrap();
    let first_peer = accept_one(&mut server);
    drop(first);
    std::thread::sleep(Duration::from_millis(50));
    let _ = server.handle_readable(first_peer);
    server.reap(first_peer);

    let mut second = UnixStream::connect(&socket).unwrap();
    let second_peer = accept_one(&mut server);
    assert_ne!(first_peer, second_peer);

    assert!(server.reply(first_peer, 1, b"late", Vec::new()).is_err());
    let _ = server.handle_writable(second_peer);
    second.set_nonblocking(true).unwrap();
    let mut received = [0u8; 64];
    assert!(
        second.read(&mut received).is_err(),
        "the new client got the reply of the old one"
    );
}

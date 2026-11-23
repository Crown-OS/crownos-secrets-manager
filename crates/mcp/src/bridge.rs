use crownos_ipc::MethodMsg;
use crownos_ipc::adapter::tokio::AsyncClient;
use secrets_protocol::secrets;
use tokio::sync::Mutex;

/// The daemon, as one agent's connection.
pub(crate) struct Bridge {
    client: Mutex<AsyncClient>,
}

impl std::fmt::Debug for Bridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Bridge").finish_non_exhaustive()
    }
}

impl Bridge {
    pub(crate) fn connect() -> Result<Self, crownos_ipc::Error> {
        Ok(Self {
            client: Mutex::new(AsyncClient::connect(secrets::SERVICE)?),
        })
    }

    pub(crate) async fn call<Method: MethodMsg>(
        &self,
        arguments: &Method::Args,
    ) -> Result<Method::Reply, crownos_ipc::Error> {
        self.client
            .lock()
            .await
            .call::<Method>(arguments, Vec::new())
            .await
    }
}

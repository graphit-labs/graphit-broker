//! Genuine TLS passthrough for the explicit single-connection fault-test pool.
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub struct CommitRelay {
    pub port: u16,
    pub armed: Arc<AtomicBool>,
    pub replies: tokio::sync::mpsc::UnboundedReceiver<tokio::sync::oneshot::Sender<bool>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl CommitRelay {
    pub async fn new(port: u16) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_port = listener.local_addr().unwrap().port();
        let armed = Arc::new(AtomicBool::new(false));
        let (replies_tx, replies) = tokio::sync::mpsc::unbounded_channel();
        let (stop, mut stopping) = tokio::sync::oneshot::channel();
        let target = armed.clone();
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopping => break,
                    accepted = listener.accept() => {
                        let (client, _) = accepted.unwrap();
                        client.set_nodelay(true).unwrap();
                        let target = target.clone();
                        let replies_tx = replies_tx.clone();
                        children.spawn(async move {
                            let peer = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                            peer.set_nodelay(true).unwrap();
                            let (mut client_read, mut client_write) = client.into_split();
                            let (mut peer_read, mut peer_write) = peer.into_split();
                            let upstream = async {
                                let mut bytes = [0u8; 8192];
                                loop {
                                    let count = client_read.read(&mut bytes).await?;
                                    if count == 0 { return Ok::<_, std::io::Error>(()); }
                                    peer_write.write_all(&bytes[..count]).await?;
                                }
                            };
                            let downstream = async {
                                let mut bytes = [0u8; 8192];
                                loop {
                                    let count = peer_read.read(&mut bytes).await?;
                                    if count == 0 { return Ok::<_, std::io::Error>(()); }
                                    if target.load(Ordering::SeqCst) {
                                        let (decision, chosen) = tokio::sync::oneshot::channel();
                                        if replies_tx.send(decision).is_err() { return Ok(()); }
                                        if !chosen.await.unwrap_or(false) {
                                            // Keep the ACK withheld, but observe server EOF so a
                                            // real connection close can finish through this relay.
                                            return tokio::io::copy(&mut peer_read, &mut tokio::io::sink())
                                                .await.map(|_| ());
                                        }
                                    }
                                    client_write.write_all(&bytes[..count]).await?;
                                }
                            };
                            tokio::select! { _ = upstream => {}, _ = downstream => {} }
                        });
                    },
                    _ = children.join_next(), if !children.is_empty() => {},
                }
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        Self {
            port: local_port,
            armed,
            replies,
            stop: Some(stop),
            task: Some(task),
        }
    }
    pub async fn close(mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.task.take().unwrap().await.unwrap();
    }
}
impl Drop for CommitRelay {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

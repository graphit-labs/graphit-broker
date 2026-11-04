//! Loopback HTTP fixture for the Broker model protocol tests.
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::JoinHandle,
};

pub(super) struct Request {
    pub(super) head: String,
    pub(super) body: Value,
}
pub(super) struct Reply {
    pub(super) status: u16,
    pub(super) body: String,
    pub(super) delay: Duration,
}
pub(super) fn reply(value: Value) -> Reply {
    Reply {
        status: 200,
        body: value.to_string(),
        delay: Duration::ZERO,
    }
}
async fn read_request(socket: &mut TcpStream) -> Request {
    let mut bytes = Vec::new();
    let end = loop {
        if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let mut buf = [0; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
        assert!(bytes.len() < 210000);
    };
    let head = String::from_utf8(bytes[..end].to_vec()).unwrap();
    let length: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(str::to_owned)
        })
        .map(|length| length.parse().unwrap())
        .unwrap_or_else(|| {
            assert!(
                head.starts_with("GET "),
                "only discovery GET may omit Content-Length"
            );
            0
        });
    while bytes.len() < end + length {
        let mut buf = [0; 4096];
        let n = socket.read(&mut buf).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
        assert!(bytes.len() <= 210000);
    }
    let body = if length == 0 && head.starts_with("GET ") {
        Value::Null
    } else {
        serde_json::from_slice(&bytes[end..end + length]).unwrap()
    };
    Request { head, body }
}
pub(super) struct Fixture {
    pub(super) origin: String,
    pub(super) observed: Arc<Notify>,
    pub(super) server: JoinHandle<Vec<Request>>,
}
pub(super) async fn fixture(replies: Vec<Reply>) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let observed = Arc::new(Notify::new());
    let signal = observed.clone();
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for reply in replies {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .expect("expected fixture request before its deadline")
                .unwrap();
            requests.push(read_request(&mut socket).await);
            let header = format!(
                "HTTP/1.1 {} fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.status,
                reply.body.len()
            );
            socket.write_all(header.as_bytes()).await.unwrap();
            signal.notify_one();
            if !reply.delay.is_zero() {
                tokio::time::sleep(reply.delay).await;
            }
            let _ = socket.write_all(reply.body.as_bytes()).await;
        }
        // Failed and cancelled operations must not send unexpected requests.
        assert!(
            tokio::time::timeout(Duration::from_millis(25), listener.accept())
                .await
                .is_err()
        );
        requests
    });
    Fixture {
        origin,
        observed,
        server,
    }
}

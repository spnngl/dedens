//! A loopback HTTP/1.1 server of files by path, for the files `dedensd` downloads.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

/// Serves each file it holds with 200 and no version tag, 404 for any other path; one request a connection.
pub(crate) struct Files {
    pub(crate) addr: SocketAddr,
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Files {
    pub(crate) fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a TCP port");
        let addr = listener.local_addr().expect("its address");
        let files = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
        let shared = Arc::clone(&files);
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut lines = BufReader::new(&stream).lines().map_while(Result::ok);
                let path = lines
                    .next()
                    .and_then(|line| line.split(' ').nth(1).map(str::to_owned))
                    .unwrap_or_default();
                // The headers, read to the blank line ending them.
                lines.find(String::is_empty);
                let files = shared.lock().unwrap_or_else(PoisonError::into_inner);
                let (status, body) = files
                    .get(&path)
                    .map_or((404, &[][..]), |body| (200, body.as_slice()));
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
            }
        });
        Self { addr, files }
    }

    /// Serves `body` at `path`, from `/`.
    pub(crate) fn serve(&self, path: &str, body: impl Into<Vec<u8>>) {
        let mut files = self.files.lock().unwrap_or_else(PoisonError::into_inner);
        files.insert(path.to_owned(), body.into());
    }

    /// The URL of `path`.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

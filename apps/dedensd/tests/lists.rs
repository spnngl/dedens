//! `dedensd` downloading the lists of a blocklist stage (D57) from a loopback HTTP server: a list blocks once
//! fetched, and after a restart from its saved copy; a SIGHUP fetches again, an unchanged list is not downloaded
//! again, and a failed download or an error page keeps the saved copy.

#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

use common::{Server, ask_udp};
use dedens_proto::{Message, Question, Rcode, RecordType};

/// What the HTTP server answers, and the version tags its requests carried.
#[derive(Debug, Default)]
struct Page {
    status: u16,
    body: String,
    etag: String,
    asked_with: Vec<Option<String>>,
}

/// A loopback HTTP/1.1 server of one page, answering 304 to a request carrying its version tag.
struct Http {
    addr: SocketAddr,
    page: Arc<Mutex<Page>>,
}

impl Http {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a TCP port");
        let addr = listener.local_addr().expect("its address");
        let page = Arc::new(Mutex::new(Page::default()));
        let shared = Arc::clone(&page);
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut tag = None;
                for line in BufReader::new(&stream).lines().map_while(Result::ok) {
                    if line.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("if-none-match")
                    {
                        tag = Some(value.trim().to_owned());
                    }
                }
                let mut page = shared.lock().unwrap_or_else(PoisonError::into_inner);
                let (status, body) = if tag.as_deref() == Some(page.etag.as_str()) {
                    (304, "")
                } else {
                    (page.status, page.body.as_str())
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nETag: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    page.etag,
                    body.len()
                );
                page.asked_with.push(tag);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self { addr, page }
    }

    /// Serves `body` with `status`, as version `etag`.
    fn serve(&self, status: u16, body: &str, etag: &str) {
        let mut page = self.page.lock().unwrap_or_else(PoisonError::into_inner);
        page.status = status;
        body.clone_into(&mut page.body);
        page.etag = format!("\"{etag}\"");
    }

    /// The version tag the last request carried.
    fn last_tag(&self) -> Option<String> {
        let page = self.page.lock().unwrap_or_else(PoisonError::into_inner);
        page.asked_with.last().cloned().flatten()
    }
}

/// A server blocking the names of the list at `url`, its copy kept in `dir`, and answering both names of the test
/// from a hosts stage otherwise.
fn blocking(listen: &str, url: &str, dir: &Path) -> String {
    format!(
        "listen: ['{listen}']\ndownloads:\n  dir: '{}'\npipeline: [block, hosts]\nstages:\n  block:\n    type: blocklist\n    urls: ['{url}']\n  hosts:\n    type: hosts\n    entries: ['192.0.2.1 ads.example tracker.example']\n",
        dir.display()
    )
}

/// Whether `server` blocks `name`.
fn blocks(server: &Server, name: &str) -> bool {
    let name = name.parse().expect("a name");
    let query = Message::query(1, Question::new(name, RecordType::A))
        .to_vec()
        .expect("a query fits");
    ask_udp(server.addr, &query).rcode() == Rcode::NXDOMAIN
}

/// A directory of its own in the temporary directory.
fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("dedensd-lists-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn downloaded_lists_block_and_outlive_failures_and_restarts() {
    let http = Http::start();
    http.serve(200, "ads.example\n", "v1");
    let url = format!("http://{}/list", http.addr);
    let dir = temp_dir();
    let mut server = Server::configured(|listen| blocking(listen, &url, &dir));
    assert!(server.event("list downloaded").is_some());
    assert!(server.event("reloaded").is_some());
    assert!(blocks(&server, "ads.example."));
    assert!(!blocks(&server, "tracker.example."));

    // A SIGHUP fetches the lists again: a new version replaces the list.
    http.serve(200, "tracker.example\n", "v2");
    server.hang_up();
    assert!(server.event("list downloaded").is_some());
    assert!(server.event("reloaded").is_some());
    assert!(blocks(&server, "tracker.example."));
    assert!(!blocks(&server, "ads.example."));

    // The same version is not downloaded again.
    server.hang_up();
    assert!(server.event("list unchanged").is_some());
    assert_eq!(http.last_tag().as_deref(), Some("\"v2\""));

    // An error page served with status 200 is not a list: the saved copy stays.
    http.serve(200, "404: Not Found", "v3");
    server.hang_up();
    assert!(
        server
            .event("list download failed, keeping the saved copy")
            .is_some()
    );
    assert!(blocks(&server, "tracker.example."));
    drop(server);

    // A start serves the saved copy at once, whatever the download does.
    http.serve(500, "", "v4");
    let mut server = Server::configured(|listen| blocking(listen, &url, &dir));
    assert!(blocks(&server, "tracker.example."));
    assert!(
        server
            .event("list download failed, keeping the saved copy")
            .is_some()
    );
    assert!(blocks(&server, "tracker.example."));
    std::fs::remove_dir_all(&dir).expect("removed");
}

/// S15.c: a list is logged by its scheme, host and path, never by the credentials or the query of its URL, and no
/// line the server writes holds them, whether its list downloads, is unchanged or fails.
#[test]
fn logged_urls_carry_no_credentials_or_query() {
    let http = Http::start();
    http.serve(200, "ads.example\n", "v1");
    let url = format!("http://user:secret@{}/list?token=t", http.addr);
    let dir = tempfile::tempdir().expect("a directory");
    let mut server = Server::configured(|listen| blocking(listen, &url, dir.path()));
    let event = server.event("list downloaded").expect("the list downloads");
    assert_eq!(event["fields"]["url"], format!("http://{}/list", http.addr));
    server.hang_up();
    assert!(server.event("list unchanged").is_some());
    http.serve(200, "404: Not Found", "v2");
    server.hang_up();
    assert!(
        server
            .event("list download failed, keeping the saved copy")
            .is_some()
    );
    let lines = server.stderr();
    assert!(lines.len() > 3, "{lines:?}");
    for line in lines {
        assert!(
            !line.contains("secret") && !line.contains("token"),
            "{line}"
        );
    }
}

/// How many lists `server` has read from a saved copy so far.
fn copies_read(server: &Server) -> usize {
    server
        .stderr()
        .iter()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| {
            event["fields"]["message"] == "list parsed" && event["fields"]["kind"] == "saved copy"
        })
        .count()
}

/// D120: a list is read once, when it downloads; the reload that follows, a SIGHUP, and a download that finds it
/// unchanged read no copy again. A start reads the copy it finds.
#[test]
fn a_downloaded_list_is_read_once() {
    let http = Http::start();
    http.serve(200, "ads.example\n", "v1");
    let url = format!("http://{}/list", http.addr);
    let dir = tempfile::tempdir().expect("a directory");
    let mut server = Server::configured(|listen| blocking(listen, &url, dir.path()));
    assert!(server.event("list downloaded").is_some());
    assert!(server.event("reloaded").is_some());
    assert!(blocks(&server, "ads.example."));
    // A SIGHUP reloads, then fetches; a list that changed reloads once more.
    server.hang_up();
    assert!(server.event("reloaded").is_some());
    assert!(server.event("list unchanged").is_some());
    http.serve(200, "tracker.example\n", "v2");
    server.hang_up();
    assert!(server.event("reloaded").is_some());
    assert!(server.event("list downloaded").is_some());
    assert!(server.event("reloaded").is_some());
    assert!(blocks(&server, "tracker.example."));
    assert_eq!(copies_read(&server), 0);
    drop(server);

    http.serve(304, "", "v2");
    let server = Server::configured(|listen| blocking(listen, &url, dir.path()));
    assert!(blocks(&server, "tracker.example."));
    assert_eq!(copies_read(&server), 1);
}

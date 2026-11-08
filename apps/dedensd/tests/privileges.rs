//! `dedensd` dropping root once its sockets are bound (D122, S5): `user:` is read, refused where it cannot be
//! followed, a no-op when the process already is that user, and, started as root on Linux, ends up as the user with
//! no capability left in any thread while it serves on :53 and reloads.
//!
//! The last test needs Linux and root, and is `#[ignore]`d: `sudo -E cargo test -p dedensd --test tests --
//! --ignored privileges::` (or in a root container). It skips with a message anywhere else.

use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use dedens_proto::{Message, Question, RecordType};
use serde_json::Value;

use crate::util::{Server, ask_tcp, ask_udp, validate, write_config};

/// A field of a `/proc/PID/status` text: `Uid`, `Gid`, `CapEff`, ...; its values, split on blanks.
fn field(status: &str, name: &str) -> Option<Vec<String>> {
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))?;
    Some(line.split_whitespace().map(str::to_owned).collect())
}

/// The status of `pid`, or of its thread `task`, where `/proc` is.
fn proc_text(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// The effective user and group of this test, `None` where there is no `/proc`.
fn running_as() -> Option<(u32, u32)> {
    let status = proc_text("/proc/self/status")?;
    let id = |name| field(&status, name)?.get(1)?.parse().ok();
    Some((id("Uid")?, id("Gid")?))
}

fn config(listen: &str, identity: &str) -> String {
    format!(
        "listen: ['{listen}']\n{identity}pipeline: [hosts]\nstages:\n  hosts:\n    type: hosts\n    entries: ['192.0.2.1 www.example']\n"
    )
}

/// D122: `user` is read where it can be followed, and refused at once where it cannot be: the OS has no drop but
/// Linux's.
#[test]
fn a_user_is_read_on_linux_and_refused_elsewhere() {
    let (code, stderr) = validate(&config("127.0.0.1:53", "user: dedens\ngroup: dedens\n"));
    if cfg!(target_os = "linux") {
        assert_eq!(code, Some(0), "{stderr}");
    } else {
        assert_eq!(code, Some(1), "{stderr}");
        assert!(
            stderr.contains("`user` drops privileges on Linux only"),
            "{stderr}"
        );
    }
    let (code, stderr) = validate(&config("127.0.0.1:53", "group: dedens\n"));
    assert_eq!(code, Some(1));
    assert!(stderr.contains("`group` needs a `user`"), "{stderr}");
}

/// D122: a server that is not root cannot become another user: it ends before binding, saying so.
#[test]
fn a_server_not_started_as_root_refuses_another_user() {
    let Some((uid, _)) = running_as().filter(|(uid, _)| *uid != 0) else {
        return eprintln!("skipped: needs Linux, and not root");
    };
    let path = write_config(&config("127.0.0.1:0", "user: root\n"));
    let output = Command::new(env!("CARGO_BIN_EXE_dedensd"))
        .arg("--config")
        .arg(path)
        .output()
        .expect("dedensd runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "`user` root needs a server started as root: it runs as uid {uid}"
        )),
        "{stderr}"
    );
}

/// D122: `user` naming the user and group the server already runs as drops nothing, says so, and the server serves.
#[test]
fn the_user_already_running_is_a_no_op() {
    let Some((uid, gid)) = running_as().filter(|(uid, _)| *uid != 0) else {
        return eprintln!("skipped: needs Linux, and not root");
    };
    let server =
        Server::configured(|listen| config(listen, &format!("user: {uid}\ngroup: {gid}\n")));
    let query = Message::query(
        7,
        Question::new("www.example.".parse().expect("a name"), RecordType::A),
    )
    .to_vec()
    .expect("a query fits");
    assert_eq!(ask_udp(server.addr, &query).answer.len(), 1);
    let stderr = server.stderr();
    assert!(
        !stderr
            .iter()
            .any(|line| line.contains("dropped privileges"))
    );
    assert!(
        stderr
            .iter()
            .any(|line| line.contains("already the user: nothing to drop")),
        "{stderr:?}"
    );
}

/// A `dedensd` started as root, killed when dropped.
struct Daemon {
    child: Child,
    events: mpsc::Receiver<Value>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn start(config: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_dedensd"))
            .arg("--config")
            .arg(config)
            .stderr(Stdio::piped())
            .spawn()
            .expect("dedensd starts");
        let stderr = child.stderr.take().expect("its piped stderr");
        let (send, events) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Ok(event) = serde_json::from_str(&line) {
                    let _ = send.send(event);
                }
            }
        });
        Self { child, events }
    }

    /// The next event with `message`, `None` after 20 s or once the server exited.
    fn event(&self, message: &str) -> Option<Value> {
        let end = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let left = end.checked_duration_since(std::time::Instant::now())?;
            let event = self.events.recv_timeout(left).ok()?;
            if event["fields"]["message"] == message {
                return Some(event);
            }
        }
    }
}

/// A directory removed when dropped, even by a failed assertion.
struct Work(std::path::PathBuf);

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A user to drop to: `dedens` if the system has it, else `nobody`.
fn target() -> Option<(String, u32)> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    ["dedens", "nobody"].into_iter().find_map(|name| {
        let line = passwd
            .lines()
            .find(|line| line.split(':').next() == Some(name))?;
        Some((name.to_owned(), line.split(':').nth(2)?.parse().ok()?))
    })
}

/// D122, the "done when" of step 14: started as root with `user:`, the server serves on :53 as that user, and no
/// thread has a capability, a user id of root, a group of root, or a way to gain privileges; a reload reads as the
/// user, and the downloads directory made before the drop belongs to it.
#[test]
#[ignore = "needs Linux, root and a free 127.0.0.1:53"]
fn root_drops_to_the_user_and_serves_on_port_53() {
    let Some((0, _)) = running_as() else {
        return eprintln!("skipped: needs Linux and root");
    };
    let Some((name, uid)) = target() else {
        return eprintln!("skipped: needs a user `dedens` or `nobody`");
    };
    let work =
        Work(std::env::temp_dir().join(format!("dedensd-privileges-{}", std::process::id())));
    let downloads = work.0.join("lists");
    let text = format!(
        "listen: ['127.0.0.1:53']\nthreads: 2\nuser: {name}\ndownloads:\n  dir: '{}'\npipeline: [hosts, block]\nstages:\n  block:\n    type: blocklist\n    urls: ['http://127.0.0.1:9/list']\n  hosts:\n    type: hosts\n    entries: ['192.0.2.1 www.example']\n",
        downloads.display()
    );
    let daemon = Daemon::start(&write_config(&text));
    assert!(
        daemon.event("dropped privileges (D122)").is_some(),
        "no drop logged"
    );
    assert!(daemon.event("serving").is_some(), "never serves");
    let pid = daemon.child.id();
    let mut tasks = 0;
    // The thread of id `pid` is the main one: listed once, among the tasks.
    let all = std::fs::read_dir(format!("/proc/{pid}/task"))
        .expect("the threads")
        .map(|task| format!("{}/status", task.expect("a thread").path().display()));
    for path in all {
        // A thread that ended since the listing has no status left.
        let Some(status) = proc_text(&path) else {
            continue;
        };
        let ids = |name| field(&status, name).expect(name);
        let uid = uid.to_string();
        assert_eq!(ids("Uid"), [uid.as_str(); 4], "{path}");
        assert!(
            ids("Gid").iter().all(|gid| gid != "0"),
            "{path}: {:?}",
            ids("Gid")
        );
        assert!(
            !ids("Groups").contains(&"0".to_owned()),
            "{path}: {:?}",
            ids("Groups")
        );
        // The bounding set stays: it limits what could be gained, which `no_new_privs` rules out.
        for caps in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            assert_eq!(ids(caps), ["0000000000000000"], "{path}: {caps}");
        }
        assert_eq!(ids("NoNewPrivs"), ["1"], "{path}");
        tasks += 1;
    }
    // The server, its signal thread, the reload thread and two serving threads.
    assert!(tasks >= 5, "{tasks} threads");
    let query = Message::query(
        7,
        Question::new("www.example.".parse().expect("a name"), RecordType::A),
    )
    .to_vec()
    .expect("a query fits");
    let address = "127.0.0.1:53".parse().expect("an address");
    for ask in [ask_tcp, ask_udp] {
        assert_eq!(ask(address, &query).answer.len(), 1);
    }
    assert_eq!(
        std::fs::metadata(&downloads)
            .expect("made before the drop")
            .uid(),
        uid
    );
    // The reload reads the configuration, as the user.
    let status = Command::new("kill")
        .arg("-HUP")
        .arg(pid.to_string())
        .status()
        .expect("kill runs");
    assert!(status.success(), "kill -HUP");
    assert!(
        daemon.event("reloaded").is_some(),
        "the reload as the user failed"
    );
}

/// D122: a configuration the user cannot read ends the start, naming `user`, not the first reload.
#[test]
#[ignore = "needs Linux, root and a free 127.0.0.1:53"]
fn a_configuration_the_user_cannot_read_ends_the_start() {
    use std::os::unix::fs::PermissionsExt as _;

    let Some((0, _)) = running_as() else {
        return eprintln!("skipped: needs Linux and root");
    };
    let Some((name, _)) = target() else {
        return eprintln!("skipped: needs a user `dedens` or `nobody`");
    };
    let path = write_config(&config("127.0.0.1:53", &format!("user: {name}\n")));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let output = Command::new(env!("CARGO_BIN_EXE_dedensd"))
        .arg("--config")
        .arg(&path)
        .output()
        .expect("dedensd runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("after dropping to `user`"), "{stderr}");
}

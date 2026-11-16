//! D154: a musl `dedensd`, its heap mimalloc's, runs without transparent huge pages (`PR_SET_THP_DISABLE`, read
//! back as `THP_enabled` in `/proc/PID/status`) unless `MIMALLOC_ALLOW_THP` is set. Each test skips where this
//! test runs without them already: the kernel has none, or the flag came from a parent.

use crate::util::Server;

fn config(listen: &str) -> String {
    format!(
        "listen: ['{listen}']\npipeline: [hosts]\nstages:\n  hosts:\n    type: hosts\n    entries: ['192.0.2.1 www.example']\n"
    )
}

/// `THP_enabled` of `/proc/<process>/status` (Linux 5.0): off once the process set `PR_SET_THP_DISABLE`, or in a
/// kernel without transparent huge pages.
fn thp_enabled(process: &str) -> bool {
    let status = std::fs::read_to_string(format!("/proc/{process}/status")).expect("its status");
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("THP_enabled:"))
        .expect("a THP_enabled line");
    value.trim() == "1"
}

/// Whether this test can see a change: it runs with transparent huge pages, and the server's environment does not
/// choose for it.
fn observable() -> bool {
    if std::env::var_os("MIMALLOC_ALLOW_THP").is_some() || !thp_enabled("self") {
        eprintln!("skipped: transparent huge pages are off here, or MIMALLOC_ALLOW_THP is set");
        return false;
    }
    true
}

#[test]
fn the_server_turns_huge_pages_off() {
    if !observable() {
        return;
    }
    let server = Server::configured(config);
    assert!(!thp_enabled(&server.pid().to_string()));
}

/// Set in lower case: mimalloc reads the name in any case, and so does `dedensd`.
#[test]
fn mimalloc_allow_thp_set_keeps_them() {
    if !observable() {
        return;
    }
    let server = Server::configured_with(&[("mimalloc_allow_thp", "1")], config);
    assert!(thp_enabled(&server.pid().to_string()));
}

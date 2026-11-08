//! Helpers shared by the tests of the command: the binary, its output, the queries a responder received.

use assert_cmd::Command;
use dedens_proto::Message;
use dedens_testkit::responder::{Responder, Transport};

/// The command, without colors and with a resolv.conf that does not exist.
pub(crate) fn dedens() -> Command {
    let mut command = assert_cmd::cargo_bin_cmd!("dedens");
    command
        .env("DEDENS_RESOLV_CONF", "/nonexistent/resolv.conf")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR_FORCE");
    command
}

/// The standard output of a run that exits with `code`.
pub(crate) fn run(args: &[&str], code: i32) -> String {
    let output = dedens()
        .args(args)
        .assert()
        .code(code)
        .get_output()
        .stdout
        .clone();
    String::from_utf8(output).expect("UTF-8")
}

/// `text` with the run's own numbers replaced by `N`: RTT, message ID, the server's port.
pub(crate) fn redact(text: &str, port: u16) -> String {
    let mut text: String = text
        .replace(&format!(":{port}"), ":PORT")
        .split_inclusive('\n')
        .map(|line| match line.split_once(" ms from ") {
            Some((head, tail)) => {
                let rtt = head.rfind(' ').map_or(0, |at| at + 1);
                format!("{}N ms from {tail}", &head[..rtt])
            }
            None => line.to_owned(),
        })
        .collect();
    for prefix in ["\"rtt_us\":", "\"id\":", "rtt_us: ", "id: "] {
        let mut out = String::new();
        let mut rest = text.as_str();
        while let Some(at) = rest.find(prefix) {
            let (before, after) = rest.split_at(at + prefix.len());
            out.push_str(before);
            let digits = after
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .unwrap_or(after.len());
            if digits > 0 {
                out.push('N');
            }
            rest = &after[digits..];
        }
        out.push_str(rest);
        text = out;
    }
    text
}

/// The queries `responder` received, decoded.
pub(crate) fn queries(responder: &Responder) -> Vec<(Transport, Message<'static>)> {
    responder
        .queries()
        .into_iter()
        .map(|(transport, wire)| {
            let message = Message::decode(&wire)
                .expect("a query")
                .message
                .into_owned();
            (transport, message)
        })
        .collect()
}

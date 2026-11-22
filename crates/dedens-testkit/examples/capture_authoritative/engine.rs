//! The container engine: the servers and tools run in the images of `testdata/authoritative/Containerfile`.

use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::Result;

/// Knot's image, with the tools `kdig`, `knsupdate`, `knotc` and `faketime`.
pub(crate) const KNOT_IMAGE: &str = "dedens-captures-knot:3.6.2";
/// NSD's image.
pub(crate) const NSD_IMAGE: &str = "dedens-captures-nsd:4.15.4";

/// A host directory made visible in a container.
pub(crate) struct Mount<'p> {
    pub(crate) host: &'p Path,
    pub(crate) container: &'static str,
    pub(crate) writable: bool,
}

/// The engine's command: `DEDENS_CONTAINER`, `docker` by default, as the justfile's `container`.
fn engine() -> Command {
    Command::new(std::env::var("DEDENS_CONTAINER").unwrap_or_else(|_| "docker".to_owned()))
}

fn mount_args(command: &mut Command, mounts: &[Mount<'_>]) {
    for mount in mounts {
        command.arg("-v").arg(format!(
            "{}:{}{}",
            mount.host.display(),
            mount.container,
            if mount.writable { "" } else { ":ro" }
        ));
    }
}

/// The text of `output`: its two streams.
pub(crate) fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Runs a tool of `image` to its end: `entrypoint` with `args`, `stdin` written to it. Its output, whether it
/// failed or not: a refused transfer is the point.
pub(crate) fn tool(
    image: &str,
    entrypoint: &str,
    args: &[&str],
    mounts: &[Mount<'_>],
    stdin: Option<&str>,
) -> Result<Output> {
    let mut command = engine();
    command.args(["run", "--rm", "-i", "--entrypoint", entrypoint]);
    mount_args(&mut command, mounts);
    command.arg(image).args(args);
    command.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        std::io::Write::write_all(&mut pipe, text.as_bytes())?;
    }
    Ok(child.wait_with_output()?)
}

/// The IPv4 address under which a container reaches the host: Docker Desktop's `host.docker.internal`.
pub(crate) fn host_address() -> Result<Ipv4Addr> {
    let output = tool(
        KNOT_IMAGE,
        "getent",
        &["ahostsv4", "host.docker.internal"],
        &[],
        None,
    )?;
    let text = text(&output);
    text.split_whitespace()
        .next()
        .and_then(|address| address.parse().ok())
        .ok_or_else(|| format!("no IPv4 address for host.docker.internal: {text}").into())
}

/// A port free for UDP and TCP on the loopback.
pub(crate) fn free_port() -> Result<u16> {
    loop {
        let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
}

/// A server running in a container, its port 53 published on `127.0.0.1:port` over UDP and TCP; removed when
/// dropped.
pub(crate) struct Container {
    name: String,
    pub(crate) port: u16,
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

impl Container {
    /// Starts `image` with `entrypoint` and `args`.
    pub(crate) fn start(
        image: &str,
        entrypoint: &str,
        args: &[&str],
        mounts: &[Mount<'_>],
    ) -> Result<Self> {
        let name = format!(
            "dedens-capture-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let port = free_port()?;
        let mut command = engine();
        command.args(["run", "-d", "--rm", "--name", &name]);
        for protocol in ["udp", "tcp"] {
            command
                .arg("-p")
                .arg(format!("127.0.0.1:{port}:53/{protocol}"));
        }
        mount_args(&mut command, mounts);
        command.args(["--entrypoint", entrypoint, image]).args(args);
        let output = command.output()?;
        if !output.status.success() {
            return Err(format!("{image} did not start: {}", text(&output)).into());
        }
        Ok(Self { name, port })
    }

    /// Runs `args` in the container: `knotc` on a running Knot.
    pub(crate) fn exec(&self, args: &[&str]) -> Result<Output> {
        Ok(engine().args(["exec", &self.name]).args(args).output()?)
    }

    /// What the server logged so far.
    pub(crate) fn logs(&self) -> Result<String> {
        Ok(text(&engine().args(["logs", &self.name]).output()?))
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = engine().args(["rm", "-f", &self.name]).output();
    }
}

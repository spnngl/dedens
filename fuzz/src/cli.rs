//! The command line of `dedens` (D32), reached through its library (D181).

use std::ffi::OsString;
use std::iter;
use std::os::unix::ffi::OsStringExt as _;

/// Reads `data` as the arguments of `dedens` after its name, separated by NUL bytes as the kernel passes them, so
/// an argument may be any bytes but NUL. A usage error is fine; a panic is a bug.
///
/// # Panics
///
/// On a bug in the reader.
pub fn parse_command_line(data: &[u8]) {
    let args = data
        .split(|&byte| byte == 0)
        .map(|arg| OsString::from_vec(arg.to_vec()));
    let _ = dedens::parse_args(iter::once(OsString::from("dedens")).chain(args));
}

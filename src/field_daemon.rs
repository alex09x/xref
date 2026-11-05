/*
 * XRef — background server that answers repeated `xref field` invocations for one binary
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A `field` search on a large binary spends most of its time loading the image and rebuilding
//! key-independent state (whole-image scan, call graph, writer index). After a slow `xref field` run,
//! the CLI starts `xref -b BIN field-daemon` in the background. The daemon keeps the image and the
//! field session in memory and listens on a private Unix socket; later `xref field` invocations for
//! the same unchanged binary and xref executable are answered by it in tens of milliseconds.
//!
//! * The socket lives in `$XDG_CACHE_HOME/xref/field-index-v1/daemon/` (mode 0700), named by a digest
//!   of the canonical input path, its device/inode/size/mtime/ctime and the same for the executable.
//! * Requests carry the full argument vector; the daemon re-parses it and answers only `field`
//!   commands for its own binary. Before every request it re-checks the metadata and exits if the
//!   input or the executable changed, so a stale daemon never answers.
//! * It exits after `XREF_FIELD_DAEMON_IDLE_SECS` (default 900) without requests.
//! * `XREF_NO_DAEMON=1` disables both using and starting it.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Local runs faster than this do not start a daemon (small binaries, tests).
const SPAWN_THRESHOLD: std::time::Duration = std::time::Duration::from_millis(250);

#[derive(serde::Serialize, serde::Deserialize)]
struct Request {
    args: Vec<String>,
    cwd: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Reply {
    ok: bool,
    stdout: String,
    error: Option<String>,
}

#[cfg(unix)]
fn stat_key(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let canonical = std::fs::canonicalize(path).ok()?;
    let meta = std::fs::metadata(&canonical).ok()?;
    let mut bytes = canonical.as_os_str().as_encoded_bytes().to_vec();
    bytes.push(0);
    for value in [meta.dev(), meta.ino(), meta.size()] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for value in [meta.mtime(), meta.mtime_nsec(), meta.ctime(), meta.ctime_nsec()] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    Some(bytes)
}

/// Identity of (input, executable); changes when either file changes.
#[cfg(unix)]
fn identity(bin: &Path) -> Option<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"xref-field-daemon-v1");
    digest.update(stat_key(bin)?);
    digest.update(stat_key(&std::env::current_exe().ok()?)?);
    Some(digest.finalize().into())
}

#[cfg(unix)]
fn socket_path(identity: &[u8; 32]) -> Option<PathBuf> {
    if std::env::var_os("XREF_NO_DAEMON").is_some() {
        return None;
    }
    let root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    let name = crate::trace_analysis::index::hex_bytes(&identity[..12]);
    let path = root.join("xref").join("field-index-v1").join("daemon").join(format!("{name}.sock"));
    // Unix socket paths are limited to ~104 bytes; skip the daemon rather than fail.
    (root.is_absolute() && path.as_os_str().len() < 100).then_some(path)
}

/// The effective uid of this process, read from the owner of a file it creates (no `unsafe`).
#[cfg(unix)]
fn own_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    static UID: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
    *UID.get_or_init(|| tempfile::tempfile().ok()?.metadata().ok().map(|meta| meta.uid()))
}

/// The socket directory is a real directory (not a symlink) owned by this user with no group/other
/// permissions, so nobody else can create, replace or read entries in it.
#[cfg(unix)]
fn private_directory(directory: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    std::fs::symlink_metadata(directory).is_ok_and(|meta| {
        meta.file_type().is_dir() && Some(meta.uid()) == own_uid() && meta.permissions().mode().trailing_zeros() >= 6
    })
}

/// The socket path is a socket (not a symlink) owned by this user inside a private directory.
#[cfg(unix)]
fn trusted_socket(path: &Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    path.parent().is_some_and(private_directory)
        && std::fs::symlink_metadata(path)
            .is_ok_and(|meta| meta.file_type().is_socket() && Some(meta.uid()) == own_uid())
}

/// Ask a running daemon to answer this `field` invocation; `None` means "run it here".
#[cfg(unix)]
#[must_use]
pub fn query(bin: &Path) -> Option<Vec<u8>> {
    use std::io::{BufRead, BufReader, Write};
    let path = socket_path(&identity(bin)?)?;
    if !trusted_socket(&path) {
        return None;
    }
    let mut stream = std::os::unix::net::UnixStream::connect(&path).ok()?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(60))).ok()?;
    let cwd = std::env::current_dir().ok()?.to_str()?.to_owned();
    let request = Request { args: std::env::args().collect(), cwd };
    writeln!(stream, "{}", serde_json::to_string(&request).ok()?).ok()?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).ok()?;
    let reply: Reply = serde_json::from_str(&line).ok()?;
    reply.ok.then(|| reply.stdout.into_bytes())
}

#[cfg(not(unix))]
#[must_use]
pub const fn query(_bin: &Path) -> Option<Vec<u8>> {
    None
}

/// After a slow local run, start a daemon for this binary in the background (best effort).
#[cfg(unix)]
pub fn spawn_after(bin: &Path, elapsed: std::time::Duration) {
    let threshold = std::env::var("XREF_FIELD_DAEMON_MIN_MS")
        .ok()
        .and_then(|ms| ms.parse().ok())
        .map_or(SPAWN_THRESHOLD, std::time::Duration::from_millis);
    if elapsed < threshold || identity(bin).and_then(|id| socket_path(&id)).is_none() {
        return;
    }
    let Ok(exe) = std::env::current_exe() else { return };
    let _ = std::process::Command::new(exe)
        .arg("-b")
        .arg(bin)
        .arg("field-daemon")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[cfg(not(unix))]
pub const fn spawn_after(_bin: &Path, _elapsed: std::time::Duration) {}

/// `xref -b BIN field-daemon`: serve `field` requests for `bin` until idle or stale.
#[cfg(unix)]
pub fn serve(bin: &Path, image: &crate::image::Image) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::ErrorKind;
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    let identity = identity(bin).ok_or("cannot identify the input")?;
    let path = socket_path(&identity).ok_or("field daemon disabled or no cache directory")?;
    let directory = path.parent().ok_or("no socket directory")?;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(directory)?;
    if !private_directory(directory) {
        return Err("field daemon directory is not private to this user; not serving".into());
    }
    if trusted_socket(&path) && UnixStream::connect(&path).is_ok() {
        return Ok(()); // another daemon already serves this binary
    }
    let _ = std::fs::remove_file(&path); // stale socket of a crashed daemon
    let listener = UnixListener::bind(&path)?;
    listener.set_nonblocking(true)?;
    let digest: [u8; 32] = Sha256::digest(&image.data).into();
    crate::serde_fields::with_image_digest(&image.data, digest, || crate::serde_fields::warm_session(image));
    let idle = std::time::Duration::from_secs(
        std::env::var("XREF_FIELD_DAEMON_IDLE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(900),
    );
    let mut last = std::time::Instant::now();
    let canonical = std::fs::canonicalize(bin)?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                last = std::time::Instant::now();
                if !answer(&stream, &canonical, image, digest, identity) {
                    break; // input or executable changed
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if last.elapsed() > idle {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Answer one connection; `false` when the daemon is stale and must exit.
#[cfg(unix)]
fn answer(
    stream: &std::os::unix::net::UnixStream,
    canonical: &Path,
    image: &crate::image::Image,
    digest: [u8; 32],
    expected: [u8; 32],
) -> bool {
    use std::io::{BufRead, BufReader, Write};
    let failure = |why: &str| Reply { ok: false, stdout: String::new(), error: Some(why.to_owned()) };
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut line = String::new();
    let fresh = identity(canonical) == Some(expected);
    let reply = if !fresh {
        failure("stale")
    } else if BufReader::new(stream).read_line(&mut line).is_err() {
        failure("read")
    } else {
        parse(&line, canonical).map_or_else(
            || failure("request"),
            |command| {
                let mut out = Vec::new();
                let run = crate::serde_fields::with_image_digest(&image.data, digest, || {
                    crate::commands::run(image, command, &mut out)
                });
                match (run, String::from_utf8(out)) {
                    (Ok(()), Ok(stdout)) => Reply { ok: true, stdout, error: None },
                    _ => failure("run"),
                }
            },
        )
    };
    let mut writer = stream;
    let _ = serde_json::to_string(&reply).map(|text| writeln!(writer, "{text}"));
    fresh
}

/// The `field` command of a request whose `-b` names this daemon's binary (relative paths are resolved
/// against the client's working directory).
#[cfg(unix)]
fn parse(line: &str, canonical: &Path) -> Option<crate::cli::Command> {
    use clap::Parser;
    let request = serde_json::from_str::<Request>(line).ok()?;
    let cli = crate::cli::Cli::try_parse_from(request.args).ok()?;
    let bin = Path::new(&request.cwd).join(cli.bin.as_deref()?);
    (matches!(cli.command, crate::cli::Command::Field { .. })
        && std::fs::canonicalize(bin).ok().as_deref() == Some(canonical))
    .then_some(cli.command)
}

#[cfg(not(unix))]
pub fn serve(_bin: &Path, _image: &crate::image::Image) -> Result<(), Box<dyn std::error::Error>> {
    Err("the field daemon needs Unix sockets".into())
}

#[cfg(all(test, unix))]
mod tests {
    use super::{parse, private_directory, trusted_socket};

    /// Only a private (0700, own, non-symlink) directory and a real socket in it are trusted.
    #[test]
    fn socket_directory_and_socket_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::path::PathBuf::from(format!("/tmp/xs{}", std::process::id()));
        let private = base.join("private");
        let open = base.join("open");
        std::fs::create_dir_all(&private).unwrap_or_default();
        std::fs::create_dir_all(&open).unwrap_or_default();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap_or_default();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap_or_default();
        let link = base.join("link");
        let _ = std::os::unix::fs::symlink(&private, &link);
        assert!(private_directory(&private));
        assert!(!private_directory(&open), "group/other access is not private");
        assert!(!private_directory(&link), "a symlinked directory is not trusted");

        let socket = private.join("s.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket);
        assert!(listener.is_ok() && trusted_socket(&socket));
        let regular = private.join("plain.sock");
        std::fs::write(&regular, b"x").unwrap_or_default();
        assert!(!trusted_socket(&regular), "a regular file is not a socket");
        let in_open = open.join("s.sock");
        let _open_listener = std::os::unix::net::UnixListener::bind(&in_open);
        assert!(!trusted_socket(&in_open), "a socket in a shared directory is not trusted");
        drop(listener);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn requests_are_accepted_only_for_field_on_this_binary() {
        let dir = std::env::temp_dir().join(format!("xref-daemon-parse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_default();
        let bin = dir.join("target");
        std::fs::write(&bin, b"x").unwrap_or_default();
        let canonical = std::fs::canonicalize(&bin).unwrap_or_default();
        let cwd = dir.to_string_lossy().into_owned();
        let request = |args: &[&str]| serde_json::json!({"args": args, "cwd": cwd}).to_string();
        // A relative -b resolves against the client's working directory.
        assert!(parse(&request(&["xref", "-b", "target", "field", "--keys", "c,m"]), &canonical).is_some());
        assert!(parse(&request(&["xref", "-b", "target", "stats"]), &canonical).is_none(), "only field");
        assert!(parse(&request(&["xref", "-b", "other", "field", "--keys", "c,m"]), &canonical).is_none());
        assert!(parse(&request(&["xref", "field", "--keys", "c,m"]), &canonical).is_none(), "no -b");
        assert!(parse("not json", &canonical).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

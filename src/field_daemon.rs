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

/// Every component from `/` to `directory` is a real directory (no symlinks) owned by root or this
/// user and not writable by group/others unless sticky (as `/tmp`). Then nobody else can rename or
/// replace any component of the path between a check and a later `connect`, `bind` or `unlink`.
#[cfg(unix)]
fn secure_ancestors(directory: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Some(uid) = own_uid() else { return false };
    directory.is_absolute()
        && directory.ancestors().all(|component| {
            std::fs::symlink_metadata(component).is_ok_and(|meta| {
                let mode = meta.permissions().mode();
                meta.file_type().is_dir()
                    && (meta.uid() == 0 || meta.uid() == uid)
                    && (mode & 0o022 == 0 || mode & 0o1000 != 0)
            })
        })
}

/// The socket path is a socket (not a symlink) owned by this user inside a private directory whose
/// whole path is secure.
#[cfg(unix)]
fn trusted_socket(path: &Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    path.parent().is_some_and(|directory| private_directory(directory) && secure_ancestors(directory))
        && std::fs::symlink_metadata(path)
            .is_ok_and(|meta| meta.file_type().is_socket() && Some(meta.uid()) == own_uid())
}

/// On Linux, the process on the other end of the connection runs as this user (`SO_PEERCRED`).
#[cfg(target_os = "linux")]
fn peer_is_self(stream: &std::os::unix::net::UnixStream) -> bool {
    rustix::net::sockopt::socket_peercred(stream).is_ok_and(|cred| cred.uid == rustix::process::getuid())
}

#[cfg(all(unix, not(target_os = "linux")))]
const fn peer_is_self(_stream: &std::os::unix::net::UnixStream) -> bool {
    true // the secure path above is the guarantee here
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
    // Non-UTF-8 arguments or working directories are not sent; the run happens locally instead.
    let args = std::env::args_os().map(|arg| arg.into_string().ok()).collect::<Option<Vec<_>>>()?;
    let cwd = std::env::current_dir().ok()?.into_os_string().into_string().ok()?;
    let mut stream = std::os::unix::net::UnixStream::connect(&path).ok()?;
    if !peer_is_self(&stream) {
        return None;
    }
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30))).ok()?;
    let request = Request { args, cwd };
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

/// Load with `load` and return the value with the input identity, only if the identity taken before
/// and after loading agree: a file replaced meanwhile is never served under the new identity.
#[cfg(unix)]
fn load_stable<T>(
    bin: &Path,
    load: impl FnOnce(&Path) -> Result<T, Box<dyn std::error::Error>>,
) -> Result<(T, [u8; 32]), Box<dyn std::error::Error>> {
    let before = identity(bin).ok_or("cannot identify the input")?;
    let value = load(bin)?;
    if identity(bin) != Some(before) {
        return Err("the input changed while it was being loaded; not serving".into());
    }
    Ok((value, before))
}

/// `xref -b BIN field-daemon`.
#[cfg(unix)]
pub fn run(bin: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (image, identity) = load_stable(bin, crate::image::Image::load)?;
    serve(bin, &image, identity)
}

#[cfg(not(unix))]
pub fn run(_bin: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Err("the field daemon needs Unix sockets".into())
}

/// Publish a listening socket at `path` without locks: bind a unique temporary name in the same
/// private directory and atomically `rename` it over `path`. Returns `None` when a live daemon already
/// answers at `path`, otherwise the listener and the inode now published.
///
/// Concurrent starters may both publish; the last `rename` wins and every daemon keeps checking
/// that `path` still names its own inode ([`still_published`]), so losers exit and exactly one stays
/// reachable. Nothing is ever unlinked by name except a daemon's own temporary or own inode, and no
/// lock can be left behind by a crash.
#[cfg(unix)]
fn claim(path: &Path) -> std::io::Result<Option<(std::os::unix::net::UnixListener, u64)>> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    if trusted_socket(path) && UnixStream::connect(path).is_ok() {
        return Ok(None);
    }
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |time| time.as_nanos());
    let temporary = path.with_extension(format!("{}.{nonce}.tmp", std::process::id()));
    let listener = UnixListener::bind(&temporary)?;
    let inode = std::fs::symlink_metadata(&temporary)?.ino();
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(Some((listener, inode)))
}

/// `path` still names the socket inode this daemon published.
#[cfg(unix)]
fn still_published(path: &Path, inode: u64) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.ino() == inode)
}

/// Serve `field` requests for `bin` until idle or stale. The socket is published only after the
/// warm-up, so a client never waits for it; on exit only this daemon's own socket inode is removed.
#[cfg(unix)]
fn serve(bin: &Path, image: &crate::image::Image, identity: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::ErrorKind;
    use std::os::unix::fs::DirBuilderExt;
    let path = socket_path(&identity).ok_or("field daemon disabled or no cache directory")?;
    let directory = path.parent().ok_or("no socket directory")?;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(directory)?;
    if !private_directory(directory) || !secure_ancestors(directory) {
        return Err("field daemon directory or one of its parents is not safe; not serving".into());
    }
    let digest: [u8; 32] = Sha256::digest(&image.data).into();
    crate::serde_fields::with_image_digest(&image.data, digest, || crate::serde_fields::warm_session(image));
    let Some((listener, own_inode)) = claim(&path)? else { return Ok(()) };
    listener.set_nonblocking(true)?;
    let mut checked = std::time::Instant::now();
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
                // Another daemon published over our socket (concurrent start): it serves now.
                if checked.elapsed() > std::time::Duration::from_secs(1) {
                    if !still_published(&path, own_inode) {
                        return Ok(());
                    }
                    checked = std::time::Instant::now();
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    // Only our own socket: a daemon that replaced it after a race keeps its socket.
    if still_published(&path, own_inode) {
        let _ = std::fs::remove_file(&path);
    }
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

#[cfg(all(test, unix))]
mod tests {
    use super::{load_stable, parse, private_directory, trusted_socket};

    /// A file replaced between the identity check and the end of loading is refused (the loader
    /// replaces it deterministically); an unchanged file is accepted.
    #[test]
    fn input_replaced_during_load_is_not_served() {
        let base = std::path::PathBuf::from(format!("/tmp/xl{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap_or_default();
        let bin = base.join("target");
        std::fs::write(&bin, b"old").unwrap_or_default();
        let stable = load_stable(&bin, |path| Ok(std::fs::read(path)?));
        assert!(stable.is_ok());
        let replaced = load_stable(&bin, |path| {
            let bytes = std::fs::read(path)?;
            let fresh = base.join("fresh");
            std::fs::write(&fresh, b"new contents")?;
            std::fs::rename(&fresh, path)?; // new inode under the same name
            Ok(bytes)
        });
        assert!(replaced.is_err(), "old bytes must not be published under the new identity");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A second daemon sees the live one and does not take over its socket; a leftover socket file
    /// with no listener is replaced by an atomic rename.
    #[test]
    fn claim_never_steals_a_live_socket() {
        use super::{claim, still_published};
        use std::os::unix::fs::PermissionsExt;
        let base = std::path::PathBuf::from(format!("/tmp/xb{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap_or_default();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap_or_default();
        let path = base.join("d.sock");
        let first = claim(&path).ok().flatten();
        assert!(first.as_ref().is_some_and(|(_, inode)| still_published(&path, *inode)));
        assert!(claim(&path).ok().flatten().is_none(), "a live daemon keeps its socket");
        drop(first); // socket file remains, nobody listens
        let second = claim(&path).ok().flatten();
        assert!(second.as_ref().is_some_and(|(_, inode)| still_published(&path, *inode)), "dead socket replaced");
        let leftovers = std::fs::read_dir(&base).map_or(0, Iterator::count);
        assert_eq!(leftovers, 1, "no temporary or lock files remain");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Two daemons starting at the same instant over a dead socket: both may publish, but exactly one
    /// remains published at the path (the other sees `still_published == false` and exits), and the
    /// published socket answers. No lock is involved, so nothing can be left stale by a crash.
    #[test]
    fn concurrent_starters_over_a_dead_socket_leave_one_daemon() {
        use super::{claim, still_published};
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{Arc, Barrier};
        for round in 0..20 {
            let base = std::path::PathBuf::from(format!("/tmp/xc{}r{round}", std::process::id()));
            std::fs::create_dir_all(&base).unwrap_or_default();
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap_or_default();
            let path = base.join("d.sock");
            drop(std::os::unix::net::UnixListener::bind(&path)); // dead socket left behind
            let barrier = Arc::new(Barrier::new(2));
            #[allow(clippy::needless_collect)] // both threads must be spawned before either is joined
            let starters: Vec<_> = (0..2)
                .map(|_| {
                    let (barrier, path) = (Arc::clone(&barrier), path.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        claim(&path).ok().flatten()
                    })
                })
                .collect();
            let published: Vec<_> = starters.into_iter().filter_map(|s| s.join().ok().flatten()).collect();
            let owners = published.iter().filter(|(_, inode)| still_published(&path, *inode)).count();
            assert_eq!(owners, 1, "round {round}: exactly one daemon stays published");
            assert!(std::os::unix::net::UnixStream::connect(&path).is_ok(), "the published daemon answers");
            drop(published);
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    /// A parent writable by others (without the sticky bit) makes the whole path untrusted.
    #[test]
    fn writable_ancestor_makes_the_path_untrusted() {
        use super::secure_ancestors;
        use std::os::unix::fs::PermissionsExt;
        let base = std::path::PathBuf::from(format!("/tmp/xa{}", std::process::id()));
        let child = base.join("daemon");
        std::fs::create_dir_all(&child).unwrap_or_default();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap_or_default();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap_or_default();
        assert!(secure_ancestors(&child));
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777)).unwrap_or_default();
        assert!(!secure_ancestors(&child), "others could rename the child");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o1777)).unwrap_or_default();
        assert!(secure_ancestors(&child), "sticky like /tmp is safe");
        let link = std::path::PathBuf::from(format!("/tmp/xal{}", std::process::id()));
        let _ = std::os::unix::fs::symlink(&base, &link);
        assert!(!secure_ancestors(&link.join("daemon")), "a symlinked component is not trusted");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Only a private (0700, own, non-symlink) directory and a real socket in it are trusted.
    #[test]
    fn socket_directory_and_socket_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::path::PathBuf::from(format!("/tmp/xs{}", std::process::id()));
        let private = base.join("private");
        let open = base.join("open");
        std::fs::create_dir_all(&private).unwrap_or_default();
        std::fs::create_dir_all(&open).unwrap_or_default();
        // Independent of the umask: the base must not be group-writable for the private case.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap_or_default();
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

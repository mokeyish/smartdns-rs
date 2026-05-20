//! Cross-platform file watcher for hot-reload of config and geo data files.
//!
//! Spawns a background OS thread holding a debouncer + watcher, and exposes a
//! tokio mpsc receiver that yields `()` whenever any of the watched paths
//! change. The thread terminates automatically when the async receiver is
//! dropped.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::log;

const DEBOUNCE_INTERVAL: Duration = Duration::from_secs(2);

/// Spawn a watcher for the given list of files.
///
/// Returns a tokio receiver that yields `()` on a debounced file change.
/// Watching the parent directory is preferred — this catches atomic renames
/// (editor "save" patterns, `mv -f new old`) that just-watching-the-file
/// misses.
pub fn spawn_watcher(paths: Vec<PathBuf>) -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel::<()>(8);

    if paths.is_empty() {
        return rx;
    }

    std::thread::spawn(move || run_watcher_thread(paths, tx));

    rx
}

fn run_watcher_thread(paths: Vec<PathBuf>, tx: mpsc::Sender<()>) {
    use notify_debouncer_mini::{new_debouncer, notify::RecursiveMode};

    let (notify_tx, notify_rx) = std::sync::mpsc::channel();

    let mut debouncer = match new_debouncer(DEBOUNCE_INTERVAL, notify_tx) {
        Ok(d) => d,
        Err(e) => {
            log::error!("hot-reload: failed to create file watcher: {}", e);
            return;
        }
    };

    // Watch the parent directories of each file (deduplicated). This handles
    // atomic renames (editor save / rm+rename) which file-level watching
    // misses. Path-level filtering is unreliable on macOS fsevent, so we
    // accept that any change in a watched dir triggers a reload; the
    // debouncer + idempotent reload keep this cheap.
    let mut watched_dirs: HashSet<PathBuf> = HashSet::new();

    for path in &paths {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if let Some(dir) = canonical.parent() {
            if watched_dirs.insert(dir.to_path_buf()) {
                match debouncer.watcher().watch(dir, RecursiveMode::NonRecursive) {
                    Ok(()) => {
                        log::info!("hot-reload: watching dir {}", dir.display());
                    }
                    Err(e) => {
                        log::warn!("hot-reload: failed to watch {}: {}", dir.display(), e);
                    }
                }
            }
        }
    }

    log::info!(
        "hot-reload: tracking {} file(s) across {} dir(s)",
        paths.len(),
        watched_dirs.len()
    );

    // Block on debounced events until the channel closes (either because the
    // async side dropped the receiver, or because the debouncer was dropped).
    for events_result in notify_rx {
        let events = match events_result {
            Ok(events) => events,
            Err(e) => {
                log::warn!("hot-reload: watcher error: {:?}", e);
                continue;
            }
        };

        // Note on filtering: on macOS, fsevent coalesces changes at directory
        // granularity, and notify's event paths aren't reliable enough to
        // filter by exact filename. We rely on (a) the 2s debouncer and
        // (b) `app.reload()` being idempotent + cheap. If a sibling file in
        // the same dir changes, we'll over-reload — that's acceptable.
        if events.is_empty() {
            continue;
        }

        log::info!(
            "hot-reload: detected {} fs event(s) in watched dir(s), triggering reload",
            events.len()
        );
        if tx.blocking_send(()).is_err() {
            break;
        }
    }

    drop(debouncer);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration as StdDuration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn watcher_fires_on_modification() {
        let dir = tempdir().expect("create tempdir");
        let path = dir.path().join("watched.dat");

        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "initial").unwrap();
        }

        let mut rx = spawn_watcher(vec![path.clone()]);

        // Let the watcher thread set up.
        tokio::time::sleep(StdDuration::from_millis(300)).await;

        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            writeln!(f, "more").unwrap();
            f.sync_all().unwrap();
        }

        // Debounce window is 2s; allow up to 6s for the event to surface.
        let recv = tokio::time::timeout(StdDuration::from_secs(6), rx.recv()).await;
        assert!(
            matches!(recv, Ok(Some(()))),
            "expected file watcher to emit on modify, got {:?}",
            recv
        );
    }

    #[tokio::test]
    async fn watcher_empty_paths_yields_no_events() {
        // spawn_watcher with no paths shouldn't spawn a thread; the sender
        // drops and the channel closes cleanly. recv() returns None, never ().
        let mut rx = spawn_watcher(vec![]);
        let recv = tokio::time::timeout(StdDuration::from_millis(500), rx.recv()).await;
        assert!(
            matches!(recv, Ok(None)),
            "expected closed channel for empty watch list, got {:?}",
            recv
        );
    }
}

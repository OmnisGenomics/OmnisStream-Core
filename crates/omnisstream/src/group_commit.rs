use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

use crate::durability::{GroupCommitConfig, GroupCommitMetrics};

#[derive(Debug)]
struct MetricsState {
    syncfs_calls: AtomicU64,
    syncfs_errors: AtomicU64,
    syncfs_nanos: AtomicU64,
    write_tokens: AtomicU64,
    waiter_tokens: AtomicU64,
    worker_wait_nanos: AtomicU64,
    max_write_batch: AtomicU64,
    max_total_batch: AtomicU64,
}

static METRICS: MetricsState = MetricsState {
    syncfs_calls: AtomicU64::new(0),
    syncfs_errors: AtomicU64::new(0),
    syncfs_nanos: AtomicU64::new(0),
    write_tokens: AtomicU64::new(0),
    waiter_tokens: AtomicU64::new(0),
    worker_wait_nanos: AtomicU64::new(0),
    max_write_batch: AtomicU64::new(0),
    max_total_batch: AtomicU64::new(0),
};

pub(crate) fn metrics_snapshot() -> GroupCommitMetrics {
    GroupCommitMetrics {
        syncfs_calls: METRICS.syncfs_calls.load(Ordering::Relaxed),
        syncfs_errors: METRICS.syncfs_errors.load(Ordering::Relaxed),
        write_tokens: METRICS.write_tokens.load(Ordering::Relaxed),
        waiter_tokens: METRICS.waiter_tokens.load(Ordering::Relaxed),
        syncfs_wall_ms: nanos_to_ms(METRICS.syncfs_nanos.load(Ordering::Relaxed)),
        worker_wait_ms: nanos_to_ms(METRICS.worker_wait_nanos.load(Ordering::Relaxed)),
        max_write_batch: METRICS.max_write_batch.load(Ordering::Relaxed),
        max_total_batch: METRICS.max_total_batch.load(Ordering::Relaxed),
    }
}

pub(crate) fn reset_metrics() {
    METRICS.syncfs_calls.store(0, Ordering::Relaxed);
    METRICS.syncfs_errors.store(0, Ordering::Relaxed);
    METRICS.syncfs_nanos.store(0, Ordering::Relaxed);
    METRICS.write_tokens.store(0, Ordering::Relaxed);
    METRICS.waiter_tokens.store(0, Ordering::Relaxed);
    METRICS.worker_wait_nanos.store(0, Ordering::Relaxed);
    METRICS.max_write_batch.store(0, Ordering::Relaxed);
    METRICS.max_total_batch.store(0, Ordering::Relaxed);
}

fn nanos_to_ms(nanos: u64) -> u64 {
    nanos / 1_000_000
}

fn duration_to_nanos(d: Duration) -> u64 {
    let nanos = d.as_nanos();
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

fn update_max(cell: &AtomicU64, value: u64) {
    let mut cur = cell.load(Ordering::Relaxed);
    while value > cur {
        match cell.compare_exchange(cur, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(v) => cur = v,
        }
    }
}

#[derive(Debug)]
pub(crate) struct WaitToken {
    rx: mpsc::Receiver<io::Result<()>>,
}

impl WaitToken {
    pub(crate) fn wait(self) -> io::Result<()> {
        let start = Instant::now();
        let res = match self.rx.recv() {
            Ok(r) => r,
            Err(_) => Err(io::Error::other("group commit batcher shutdown")),
        };
        METRICS
            .worker_wait_nanos
            .fetch_add(duration_to_nanos(start.elapsed()), Ordering::Relaxed);
        res
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenKind {
    Write,
    Waiter,
}

#[derive(Debug)]
struct Token {
    kind: TokenKind,
    done: mpsc::Sender<io::Result<()>>,
}

#[derive(Debug)]
enum Message {
    Token(Token),
    Shutdown,
}

#[derive(Debug)]
struct State {
    pending_writes: AtomicUsize,
    last_error: Mutex<Option<String>>,
}

pub(crate) struct DurabilityBatcher {
    cfg: GroupCommitConfig,
    state: Arc<State>,
    submit_lock: Mutex<()>,
    tx: mpsc::Sender<Message>,
    join: Mutex<Option<thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for DurabilityBatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurabilityBatcher")
            .field("cfg", &self.cfg)
            .field(
                "pending_writes",
                &self.state.pending_writes.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl DurabilityBatcher {
    pub(crate) fn start(root: &Path, cfg: GroupCommitConfig) -> io::Result<Arc<Self>> {
        let root_dir = File::open(root)?;

        let (tx, rx) = mpsc::channel::<Message>();
        let state = Arc::new(State {
            pending_writes: AtomicUsize::new(0),
            last_error: Mutex::new(None),
        });

        let batcher = Arc::new(Self {
            cfg,
            state: Arc::clone(&state),
            submit_lock: Mutex::new(()),
            tx,
            join: Mutex::new(None),
        });

        let join = thread::spawn(move || worker(root_dir, rx, cfg, state));
        *batcher.join.lock().unwrap() = Some(join);
        Ok(batcher)
    }

    pub(crate) fn lock_submission(&self) -> std::sync::MutexGuard<'_, ()> {
        self.submit_lock.lock().unwrap()
    }

    pub(crate) fn submit_write_locked(&self) -> io::Result<WaitToken> {
        self.submit_locked(TokenKind::Write)
    }

    pub(crate) fn flush_if_pending_locked(&self) -> io::Result<Option<WaitToken>> {
        if self.state.pending_writes.load(Ordering::Relaxed) == 0 {
            return Ok(None);
        }
        Ok(Some(self.submit_locked(TokenKind::Waiter)?))
    }

    fn submit_locked(&self, kind: TokenKind) -> io::Result<WaitToken> {
        if let Some(err) = self.last_error_message() {
            return Err(io::Error::other(err));
        }

        let (tx_done, rx_done) = mpsc::channel::<io::Result<()>>();
        if kind == TokenKind::Write {
            self.state.pending_writes.fetch_add(1, Ordering::Relaxed);
        }

        if self
            .tx
            .send(Message::Token(Token {
                kind,
                done: tx_done,
            }))
            .is_err()
        {
            if kind == TokenKind::Write {
                self.state.pending_writes.fetch_sub(1, Ordering::Relaxed);
            }
            return Err(io::Error::other("group commit batcher stopped"));
        }

        Ok(WaitToken { rx: rx_done })
    }

    fn last_error_message(&self) -> Option<String> {
        match self.state.last_error.lock() {
            Ok(g) => g.clone(),
            Err(e) => e.into_inner().clone(),
        }
    }
}

impl Drop for DurabilityBatcher {
    fn drop(&mut self) {
        let _ = self.tx.send(Message::Shutdown);

        let join = self.join.lock().ok().and_then(|mut j| j.take());
        if let Some(join) = join {
            let _ = join.join();
        }
    }
}

fn worker(root_dir: File, rx: mpsc::Receiver<Message>, cfg: GroupCommitConfig, state: Arc<State>) {
    loop {
        let msg = match rx.recv() {
            Ok(m) => m,
            Err(_) => break,
        };

        let mut shutdown = false;
        let mut batch = Vec::new();
        let mut write_count = 0_usize;

        match msg {
            Message::Token(t) => {
                if t.kind == TokenKind::Write {
                    write_count += 1;
                }
                batch.push(t);
            }
            Message::Shutdown => break,
        }

        let deadline = Instant::now() + Duration::from_millis(cfg.window_ms);
        while batch.len() < cfg.max_ops {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let timeout = deadline - now;

            match rx.recv_timeout(timeout) {
                Ok(Message::Token(t)) => {
                    if t.kind == TokenKind::Write {
                        write_count += 1;
                    }
                    batch.push(t);
                }
                Ok(Message::Shutdown) => {
                    shutdown = true;
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    shutdown = true;
                    break;
                }
            }
        }

        let total_tokens = batch.len() as u64;
        let write_tokens = write_count as u64;
        METRICS
            .write_tokens
            .fetch_add(write_tokens, Ordering::Relaxed);
        METRICS
            .waiter_tokens
            .fetch_add(total_tokens.saturating_sub(write_tokens), Ordering::Relaxed);
        update_max(&METRICS.max_write_batch, write_tokens);
        update_max(&METRICS.max_total_batch, total_tokens);

        let barrier_res = if write_count == 0 {
            Ok(())
        } else {
            barrier_syncfs(&root_dir)
        };

        match barrier_res {
            Ok(()) => {
                if let Ok(mut e) = state.last_error.lock() {
                    *e = None;
                }
                for t in batch.drain(..) {
                    let _ = t.done.send(Ok(()));
                }
            }
            Err(err) => {
                let kind = err.kind();
                let msg = err.to_string();
                if let Ok(mut e) = state.last_error.lock() {
                    *e = Some(msg.clone());
                }
                for t in batch.drain(..) {
                    let _ = t.done.send(Err(io::Error::new(kind, msg.clone())));
                }
            }
        }

        if write_count > 0 {
            state
                .pending_writes
                .fetch_sub(write_count, Ordering::Relaxed);
        }

        if shutdown {
            break;
        }
    }
}

fn barrier_syncfs(root_dir: &File) -> io::Result<()> {
    if crate::durability::relaxed_durability_enabled() {
        return Ok(());
    }
    METRICS.syncfs_calls.fetch_add(1, Ordering::Relaxed);
    let start = Instant::now();
    let res = rustix::fs::syncfs(root_dir)
        .map_err(|errno| io::Error::from_raw_os_error(errno.raw_os_error()));
    METRICS
        .syncfs_nanos
        .fetch_add(duration_to_nanos(start.elapsed()), Ordering::Relaxed);
    if res.is_err() {
        METRICS.syncfs_errors.fetch_add(1, Ordering::Relaxed);
    }
    res
}

//! Per-connection outbox: a bounded queue with a byte budget.

use super::*;

/// Frames queued for one connection at most (besides the byte budget).
pub(crate) const MAX_QUEUED_FRAMES: usize = 1024;

/// A connection's outbox: a bounded queue of frames with a byte budget, plus a
/// close signal that works even when the queue is full.
#[derive(Clone)]
pub(crate) struct Tx {
    pub(crate) q: mpsc::Sender<(Frame, usize)>,
    pub(crate) queued: Arc<AtomicUsize>,
    pub(crate) budget: usize,
    pub(crate) close: Arc<Notify>,
}

impl Tx {
    pub(crate) fn new(budget: usize) -> (Self, mpsc::Receiver<(Frame, usize)>) {
        let (q, rx) = mpsc::channel(MAX_QUEUED_FRAMES);
        let tx = Self {
            q,
            queued: Arc::new(AtomicUsize::new(0)),
            budget,
            close: Arc::new(Notify::new()),
        };
        (tx, rx)
    }

    /// Ask the connection to close (for example because the device reconnected).
    pub(crate) fn close(&self) {
        self.close.notify_one();
    }
}

/// Queue `frame` (dropped if the connection's outbox is full).
pub(crate) fn send(tx: &Tx, frame: Frame) {
    queue(tx, frame);
}

/// Queue `frame`; `false` if the connection's outbox is full, so the frame was
/// dropped. One frame always fits into an empty outbox.
pub(crate) fn queue(tx: &Tx, frame: Frame) -> bool {
    let n = approx_size(&frame);
    let before = tx.queued.fetch_add(n, Ordering::Relaxed);
    if (before > 0 && before + n > tx.budget) || tx.q.try_send((frame, n)).is_err() {
        tx.queued.fetch_sub(n, Ordering::Relaxed);
        return false;
    }
    true
}

/// Roughly the memory a queued frame holds.
pub(crate) fn approx_size(f: &Frame) -> usize {
    256 + match f {
        Frame::Broadcast { body, .. }
        | Frame::Direct { body, .. }
        | Frame::SyncRequest { body, .. }
        | Frame::InviteClaim { body, .. }
        | Frame::Deliver { body, .. }
        | Frame::ClaimDeliver { body, .. } => body.len(),
        Frame::Presence { online, .. } => online.len() * 80,
        Frame::Receipt { delivered } => delivered.len() * 80,
        Frame::Error { message, .. } => message.len(),
        _ => 0,
    }
}

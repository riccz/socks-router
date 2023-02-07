use std::path::Path;
use std::time::{Duration, Instant};

use notify::{recommended_watcher, Event, RecommendedWatcher, RecursiveMode, Result, Watcher};
use tokio::sync::mpsc;

/// Wrap a RecommendedWatcher for async usage
pub struct AsyncWatcher {
    watcher: RecommendedWatcher,
    rx: mpsc::UnboundedReceiver<Result<Event>>,
}

impl AsyncWatcher {
    pub fn new() -> Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let watcher = recommended_watcher(move |res| tx.send(res).expect("Dropped the receiver"))?;
        Ok(Self { rx, watcher })
    }

    pub fn watch<P: AsRef<Path>>(&mut self, path: P, recursive_mode: RecursiveMode) -> Result<()> {
        self.watcher.watch(path.as_ref(), recursive_mode)
    }

    /// Get the next Event
    pub async fn next(&mut self) -> Result<Event> {
        self.rx.recv().await.expect("Dropped the sender")
    }

    /// Get the next event that satisfies the predicate
    async fn next_filter<F: Fn(&Event) -> bool>(&mut self, predicate: F) -> Result<Event> {
        loop {
            let event = self.next().await?;
            if predicate(&event) {
                return Ok(event);
            }
        }
    }

    pub async fn next_debounced(&mut self, interval: Duration) -> Result<Vec<Event>> {
        self.next_debounced_filter(interval, |_| true).await
    }

    /// Accumulate some events for a max duration, then return them all at once
    ///
    /// Events for which the predicate evaluates to false will be ignored
    pub async fn next_debounced_filter<F>(
        &mut self,
        interval: Duration,
        predicate: F,
    ) -> Result<Vec<Event>>
    where
        F: Fn(&Event) -> bool,
    {
        // First event
        let mut events = vec![self.next_filter(&predicate).await?];
        let t_first = Instant::now();

        loop {
            // Wait at most until t_first + interval
            let sleep_interval = interval - t_first.elapsed();
            tokio::select! {
                res = self.next_filter(&predicate) => events.push(res?),
                _ = tokio::time::sleep(sleep_interval) => {}
            }
            if t_first.elapsed() >= interval {
                return Ok(events);
            }
        }
    }
}

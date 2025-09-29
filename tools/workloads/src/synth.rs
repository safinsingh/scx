use std::{
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn thread_fn(deadline: Instant) -> u64 {
    let mut per_thread_count = 0;

    while Instant::now() < deadline {
        COUNTER.fetch_add(1, Ordering::Relaxed);
        per_thread_count += 1;
    }

    return per_thread_count;
}

fn main() {
    let num_threads = 3;
    let num_secs = 10;

    let deadline = Instant::now() + Duration::from_secs(num_secs);
    let handles = (0..num_threads)
        .map(|_| thread::spawn(move || thread_fn(deadline)))
        .collect::<Vec<_>>();
    let thread_counts = handles
        .into_iter()
        .map(|th| th.join().unwrap())
        .collect::<Vec<_>>();

    println!(
        "Throughput: {} ops/sec -- {:?}",
        COUNTER.load(Ordering::SeqCst) / num_secs,
        thread_counts
    )
}

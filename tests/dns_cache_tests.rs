use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use rws::{
    dependencies::{BoxFuture, Resolver},
    infrastructure::dns::CachedResolver,
    runtime::RuntimeResult,
};

#[derive(Default)]
struct CountingResolver {
    calls: AtomicUsize,
}

impl CountingResolver {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Resolver for CountingResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, RuntimeResult<String>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("{host}-resolved"))
        })
    }
}

#[tokio::test]
async fn cached_resolver_reuses_answer_within_ttl() {
    let inner = Arc::new(CountingResolver::default());
    let resolver = CachedResolver::new(inner.clone(), Duration::from_secs(60), 32);

    let first = resolver.resolve("example.com").await.unwrap();
    let second = resolver.resolve("example.com").await.unwrap();

    assert_eq!(first, "example.com-resolved");
    assert_eq!(second, first);
    assert_eq!(inner.calls(), 1);
}

#[tokio::test]
async fn cached_resolver_refreshes_answer_after_ttl() {
    let inner = Arc::new(CountingResolver::default());
    let resolver = CachedResolver::new(inner.clone(), Duration::from_millis(10), 32);

    resolver.resolve("example.com").await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    resolver.resolve("example.com").await.unwrap();

    assert_eq!(inner.calls(), 2);
}

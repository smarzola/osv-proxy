use crate::artifact::Ecosystem;
use crate::config::MetadataCacheConfig;
use crate::response::BufferedResponseBody;
use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode, Version};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::sync::{Notify, Semaphore};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct MetadataCacheKey {
    pub ecosystem: Ecosystem,
    pub revision: Option<u64>,
    pub path: String,
    pub accept: Option<Vec<u8>>,
    pub if_none_match: Option<Vec<u8>>,
    pub if_modified_since: Option<Vec<u8>>,
    pub range: Option<Vec<u8>>,
    pub if_range: Option<Vec<u8>>,
}

impl MetadataCacheKey {
    fn weight(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.path.len()
            + option_len(&self.accept)
            + option_len(&self.if_none_match)
            + option_len(&self.if_modified_since)
            + option_len(&self.range)
            + option_len(&self.if_range)
    }
}

fn option_len(value: &Option<Vec<u8>>) -> usize {
    value.as_ref().map_or(0, Vec::len)
}

pub(crate) struct MetadataFill {
    pub response: Response<Body>,
    pub overloaded: bool,
    pub valid_until: Option<DateTime<Utc>>,
    pub policy_cacheable: bool,
}

pub(crate) struct MetadataCache {
    enabled: bool,
    capacity_bytes: usize,
    max_entry_bytes: usize,
    ttl: std::time::Duration,
    fills: Arc<Semaphore>,
    state: Mutex<CacheState>,
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<Arc<MetadataCacheKey>, usize>,
    nodes: Vec<Option<CacheEntry>>,
    free_nodes: Vec<usize>,
    lru_head: Option<usize>,
    lru_tail: Option<usize>,
    inflight: HashMap<MetadataCacheKey, Arc<Inflight>>,
    total_weight: usize,
}

struct CacheEntry {
    key: Arc<MetadataCacheKey>,
    response: Arc<CachedResponse>,
    expires_at: Instant,
    weight: usize,
    previous: Option<usize>,
    next: Option<usize>,
}

#[derive(Default)]
struct Inflight {
    result: Mutex<Option<Arc<CachedResponse>>>,
    notify: Notify,
}

struct CachedResponse {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
    overloaded: bool,
}

impl CachedResponse {
    fn from_fill(fill: &MetadataFill) -> Option<Self> {
        let body = fill
            .response
            .extensions()
            .get::<BufferedResponseBody>()?
            .0
            .clone();
        Some(Self {
            status: fill.response.status(),
            version: fill.response.version(),
            headers: fill.response.headers().clone(),
            body,
            overloaded: fill.overloaded,
        })
    }

    fn weight(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.body.len()
            + self
                .headers
                .iter()
                .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
                .sum::<usize>()
    }

    fn to_http_response(&self) -> Response<Body> {
        let mut response = Response::new(Body::from(self.body.clone()));
        *response.status_mut() = self.status;
        *response.version_mut() = self.version;
        *response.headers_mut() = self.headers.clone();
        response
            .extensions_mut()
            .insert(BufferedResponseBody(self.body.clone()));
        response
    }
}

enum Lookup {
    Hit(Arc<CachedResponse>),
    Wait(Arc<Inflight>),
    Fill(Arc<Inflight>),
}

impl MetadataCache {
    pub(crate) fn new(config: &MetadataCacheConfig) -> Arc<Self> {
        Arc::new(Self {
            enabled: config.enabled,
            capacity_bytes: config.capacity_bytes,
            max_entry_bytes: config.max_entry_bytes,
            ttl: config.ttl,
            fills: Arc::new(Semaphore::new(config.fill_concurrency)),
            state: Mutex::new(CacheState::default()),
        })
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) async fn execute<F, Fut>(
        self: &Arc<Self>,
        key: MetadataCacheKey,
        fill: F,
    ) -> (Response<Body>, bool)
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = MetadataFill> + Send,
    {
        if !self.enabled {
            let fill = fill().await;
            return (fill.response, fill.overloaded);
        }

        let mut fill = Some(fill);
        loop {
            match self.lookup(&key) {
                Lookup::Hit(response) => {
                    return (response.to_http_response(), response.overloaded);
                }
                Lookup::Wait(inflight) => {
                    let notified = inflight.notify.notified();
                    if let Some(response) = lock(&inflight.result).clone() {
                        return (response.to_http_response(), response.overloaded);
                    }
                    notified.await;
                    if let Some(response) = lock(&inflight.result).clone() {
                        return (response.to_http_response(), response.overloaded);
                    }
                }
                Lookup::Fill(inflight) => {
                    let mut leader =
                        FillLeader::new(Arc::clone(self), key.clone(), Arc::clone(&inflight));
                    let _permit = Arc::clone(&self.fills)
                        .acquire_owned()
                        .await
                        .expect("metadata cache fill semaphore remains open");
                    let completed = fill.take().expect("fill closure is consumed once")().await;
                    let Some(response) = CachedResponse::from_fill(&completed).map(Arc::new) else {
                        leader.finish(None, None);
                        return (completed.response, completed.overloaded);
                    };
                    let expires_at = self.expiration(completed.valid_until);
                    let cacheable = response.status == StatusCode::OK
                        && !response.overloaded
                        && completed.policy_cacheable
                        && response.body.len() <= self.max_entry_bytes
                        && expires_at.is_some();
                    leader.finish(
                        Some(Arc::clone(&response)),
                        cacheable.then_some(expires_at.expect("cacheable expiry exists")),
                    );
                    return (response.to_http_response(), response.overloaded);
                }
            }
        }
    }

    fn lookup(&self, key: &MetadataCacheKey) -> Lookup {
        let now = Instant::now();
        let mut state = lock(&self.state);
        if let Some(index) = state.entries.get(key).copied() {
            if state.node(index).expires_at <= now {
                state.remove_index(index);
            } else {
                let response = Arc::clone(&state.node(index).response);
                state.touch(index);
                return Lookup::Hit(response);
            }
        }
        if let Some(inflight) = state.inflight.get(key) {
            return Lookup::Wait(Arc::clone(inflight));
        }
        let inflight = Arc::new(Inflight::default());
        state.inflight.insert(key.clone(), Arc::clone(&inflight));
        Lookup::Fill(inflight)
    }

    fn expiration(&self, valid_until: Option<DateTime<Utc>>) -> Option<Instant> {
        let now = Instant::now();
        let mut lifetime = self.ttl;
        if let Some(valid_until) = valid_until {
            let remaining = valid_until
                .signed_duration_since(Utc::now())
                .to_std()
                .ok()?;
            if remaining.is_zero() {
                return None;
            }
            lifetime = lifetime.min(remaining);
        }
        now.checked_add(lifetime)
    }

    fn complete(
        &self,
        key: &MetadataCacheKey,
        inflight: &Arc<Inflight>,
        response: Option<Arc<CachedResponse>>,
        expires_at: Option<Instant>,
    ) {
        let mut state = lock(&self.state);
        *lock(&inflight.result) = response.clone();
        if let (Some(response), Some(expires_at)) = (response.as_ref(), expires_at) {
            let weight = key.weight().saturating_add(response.weight());
            if weight <= self.capacity_bytes {
                state.insert(
                    key.clone(),
                    Arc::clone(response),
                    expires_at,
                    weight,
                    self.capacity_bytes,
                );
            }
        }
        if state
            .inflight
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, inflight))
        {
            state.inflight.remove(key);
        }
        drop(state);
        inflight.notify.notify_waiters();
    }

    fn abandon(&self, key: &MetadataCacheKey, inflight: &Arc<Inflight>) {
        let mut state = lock(&self.state);
        if state
            .inflight
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, inflight))
        {
            state.inflight.remove(key);
        }
        drop(state);
        inflight.notify.notify_waiters();
    }

    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        lock(&self.state).entries.len()
    }
}

impl CacheState {
    fn insert(
        &mut self,
        key: MetadataCacheKey,
        response: Arc<CachedResponse>,
        expires_at: Instant,
        weight: usize,
        capacity: usize,
    ) {
        self.remove(&key);
        while self.total_weight.saturating_add(weight) > capacity {
            let Some(oldest) = self.lru_head else {
                break;
            };
            self.remove_index(oldest);
        }

        let key = Arc::new(key);
        let index = if let Some(index) = self.free_nodes.pop() {
            index
        } else {
            self.nodes.push(None);
            self.nodes.len() - 1
        };
        let previous = self.lru_tail;
        self.nodes[index] = Some(CacheEntry {
            key: Arc::clone(&key),
            response,
            expires_at,
            weight,
            previous,
            next: None,
        });
        if let Some(previous) = previous {
            self.node_mut(previous).next = Some(index);
        } else {
            self.lru_head = Some(index);
        }
        self.lru_tail = Some(index);
        self.total_weight = self.total_weight.saturating_add(weight);
        self.entries.insert(key, index);
    }

    fn remove(&mut self, key: &MetadataCacheKey) {
        if let Some(index) = self.entries.get(key).copied() {
            self.remove_index(index);
        }
    }

    fn remove_index(&mut self, index: usize) {
        let Some(entry) = self.nodes.get_mut(index).and_then(Option::take) else {
            return;
        };
        self.entries.remove(entry.key.as_ref());
        if let Some(previous) = entry.previous {
            self.node_mut(previous).next = entry.next;
        } else {
            self.lru_head = entry.next;
        }
        if let Some(next) = entry.next {
            self.node_mut(next).previous = entry.previous;
        } else {
            self.lru_tail = entry.previous;
        }
        self.total_weight = self.total_weight.saturating_sub(entry.weight);
        self.free_nodes.push(index);
    }

    fn touch(&mut self, index: usize) {
        if self.lru_tail == Some(index) {
            return;
        }
        let (previous, next) = {
            let entry = self.node(index);
            (entry.previous, entry.next)
        };
        if let Some(previous) = previous {
            self.node_mut(previous).next = next;
        } else {
            self.lru_head = next;
        }
        if let Some(next) = next {
            self.node_mut(next).previous = previous;
        }

        let previous_tail = self.lru_tail;
        {
            let entry = self.node_mut(index);
            entry.previous = previous_tail;
            entry.next = None;
        }
        if let Some(previous_tail) = previous_tail {
            self.node_mut(previous_tail).next = Some(index);
        } else {
            self.lru_head = Some(index);
        }
        self.lru_tail = Some(index);
    }

    fn node(&self, index: usize) -> &CacheEntry {
        self.nodes[index]
            .as_ref()
            .expect("metadata cache index points to a live node")
    }

    fn node_mut(&mut self, index: usize) -> &mut CacheEntry {
        self.nodes[index]
            .as_mut()
            .expect("metadata cache index points to a live node")
    }
}

struct FillLeader {
    cache: Arc<MetadataCache>,
    key: MetadataCacheKey,
    inflight: Arc<Inflight>,
    completed: bool,
}

impl FillLeader {
    fn new(cache: Arc<MetadataCache>, key: MetadataCacheKey, inflight: Arc<Inflight>) -> Self {
        Self {
            cache,
            key,
            inflight,
            completed: false,
        }
    }

    fn finish(&mut self, response: Option<Arc<CachedResponse>>, expires_at: Option<Instant>) {
        self.cache
            .complete(&self.key, &self.inflight, response, expires_at);
        self.completed = true;
    }
}

impl Drop for FillLeader {
    fn drop(&mut self) {
        if !self.completed {
            self.cache.abandon(&self.key, &self.inflight);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::RegistryResponse;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn config() -> MetadataCacheConfig {
        MetadataCacheConfig {
            enabled: true,
            capacity_bytes: 4096,
            max_entry_bytes: 1024,
            ttl: Duration::from_secs(60),
            fill_concurrency: 2,
        }
    }

    fn key(path: &str, revision: u64) -> MetadataCacheKey {
        MetadataCacheKey {
            ecosystem: Ecosystem::Npm,
            revision: Some(revision),
            path: path.to_string(),
            accept: None,
            if_none_match: None,
            if_modified_since: None,
            range: None,
            if_range: None,
        }
    }

    fn fill_response(status: u16, body: &str) -> MetadataFill {
        MetadataFill {
            response: RegistryResponse {
                status,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: body.as_bytes().to_vec(),
            }
            .into_http_response(),
            overloaded: false,
            valid_until: None,
            policy_cacheable: true,
        }
    }

    async fn body(response: Response<Body>) -> Bytes {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn repeated_requests_share_one_fill_and_immutable_bytes() {
        let cache = MetadataCache::new(&config());
        let fills = Arc::new(AtomicUsize::new(0));
        let first = cache
            .execute(key("/npm/demo", 1), {
                let fills = Arc::clone(&fills);
                move || async move {
                    fills.fetch_add(1, Ordering::SeqCst);
                    fill_response(200, "filtered")
                }
            })
            .await
            .0;
        let first_bytes = first
            .extensions()
            .get::<BufferedResponseBody>()
            .unwrap()
            .0
            .clone();
        let second = cache
            .execute(key("/npm/demo", 1), || async {
                fill_response(200, "unexpected")
            })
            .await
            .0;
        let second_bytes = second
            .extensions()
            .get::<BufferedResponseBody>()
            .unwrap()
            .0
            .clone();

        assert_eq!(fills.load(Ordering::SeqCst), 1);
        assert_eq!(body(first).await, &b"filtered"[..]);
        assert_eq!(body(second).await, &b"filtered"[..]);
        assert_eq!(first_bytes.as_ptr(), second_bytes.as_ptr());
    }

    #[tokio::test]
    async fn concurrent_identical_misses_coalesce() {
        let cache = MetadataCache::new(&config());
        let fills = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let tasks = (0..8)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let fills = Arc::clone(&fills);
                let release = Arc::clone(&release);
                tokio::spawn(async move {
                    cache
                        .execute(key("/npm/demo", 1), move || async move {
                            fills.fetch_add(1, Ordering::SeqCst);
                            release.notified().await;
                            fill_response(200, "filtered")
                        })
                        .await
                        .0
                })
            })
            .collect::<Vec<_>>();
        while fills.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        release.notify_waiters();
        for task in tasks {
            assert_eq!(body(task.await.unwrap()).await, &b"filtered"[..]);
        }
        assert_eq!(fills.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn revision_and_representation_headers_are_distinct_keys() {
        let cache = MetadataCache::new(&config());
        let fills = Arc::new(AtomicUsize::new(0));
        let mut html_key = key("/pypi/simple/demo/", 2);
        html_key.accept = Some(b"text/html".to_vec());
        for cache_key in [
            key("/pypi/simple/demo/", 1),
            key("/pypi/simple/demo/", 2),
            html_key,
        ] {
            cache
                .execute(cache_key, {
                    let fills = Arc::clone(&fills);
                    move || async move {
                        fills.fetch_add(1, Ordering::SeqCst);
                        fill_response(200, "filtered")
                    }
                })
                .await;
        }
        assert_eq!(fills.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn uncacheable_revision_failures_respect_unique_fill_bound() {
        let cache = MetadataCache::new(&config());
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Semaphore::new(0));
        let tasks = (0..8)
            .map(|index| {
                let cache = Arc::clone(&cache);
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                let release = Arc::clone(&release);
                tokio::spawn(async move {
                    let mut cache_key = key(&format!("/npm/demo-{index}"), 1);
                    cache_key.revision = None;
                    cache
                        .execute(cache_key, move || async move {
                            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(current, Ordering::SeqCst);
                            release.acquire().await.unwrap().forget();
                            active.fetch_sub(1, Ordering::SeqCst);
                            let mut fill = fill_response(200, "filtered");
                            fill.policy_cacheable = false;
                            fill
                        })
                        .await
                })
            })
            .collect::<Vec<_>>();
        while active.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
        assert_eq!(active.load(Ordering::SeqCst), 2);
        release.add_permits(tasks.len());
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn large_population_hot_hits_do_not_scan_the_cache() {
        const ENTRIES: usize = 20_000;
        let mut cache_config = config();
        cache_config.capacity_bytes = 64 * 1024 * 1024;
        let cache = MetadataCache::new(&cache_config);
        for index in 0..ENTRIES {
            cache
                .execute(key(&format!("/npm/demo-{index}"), 1), || async {
                    fill_response(200, "x")
                })
                .await;
        }
        assert_eq!(cache.entry_count(), ENTRIES);

        let started = Instant::now();
        for _ in 0..ENTRIES {
            assert!(matches!(
                cache.lookup(&key("/npm/demo-10000", 1)),
                Lookup::Hit(_)
            ));
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "20,000 hot hits over 20,000 entries took {:?}; lookup likely scans the cache",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn disabled_unsuccessful_and_oversized_responses_are_not_retained() {
        let mut disabled = config();
        disabled.enabled = false;
        let disabled = MetadataCache::new(&disabled);
        for _ in 0..2 {
            disabled
                .execute(key("/npm/disabled", 1), || async {
                    fill_response(200, "disabled")
                })
                .await;
        }
        assert_eq!(disabled.entry_count(), 0);

        let cache = MetadataCache::new(&config());
        for (path, status, body) in [
            ("/npm/error", 502, "error".to_string()),
            ("/npm/large", 200, "x".repeat(1025)),
        ] {
            for _ in 0..2 {
                cache
                    .execute(key(path, 1), {
                        let body = body.clone();
                        move || async move { fill_response(status, &body) }
                    })
                    .await;
            }
        }

        cache
            .execute(key("/npm/overloaded", 1), || async {
                let mut fill = fill_response(200, "overloaded");
                fill.overloaded = true;
                fill
            })
            .await;
        cache
            .execute(key("/npm/unstable-policy", 1), || async {
                let mut fill = fill_response(200, "fail-open");
                fill.policy_cacheable = false;
                fill
            })
            .await;
        assert_eq!(cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn ttl_age_transition_and_capacity_evict_entries() {
        let mut cache_config = config();
        cache_config.ttl = Duration::from_millis(10);
        cache_config.capacity_bytes = 500;
        let cache = MetadataCache::new(&cache_config);
        cache
            .execute(key("/npm/one", 1), || async {
                fill_response(200, &"a".repeat(120))
            })
            .await;
        cache
            .execute(key("/npm/two", 1), || async {
                fill_response(200, &"b".repeat(120))
            })
            .await;
        assert!(cache.entry_count() <= 1);

        tokio::time::sleep(Duration::from_millis(15)).await;
        cache
            .execute(key("/npm/two", 1), || async {
                fill_response(200, "refilled")
            })
            .await;
        assert_eq!(
            body(
                cache
                    .execute(key("/npm/two", 1), || async {
                        fill_response(200, "unexpected")
                    })
                    .await
                    .0
            )
            .await,
            &b"refilled"[..]
        );

        let expiring = MetadataCache::new(&config());
        expiring
            .execute(key("/npm/age", 1), || async {
                let mut fill = fill_response(200, "young-filtered");
                fill.valid_until = Some(Utc::now() + chrono::Duration::milliseconds(5));
                fill
            })
            .await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            body(
                expiring
                    .execute(key("/npm/age", 1), || async {
                        fill_response(200, "age-refiltered")
                    })
                    .await
                    .0
            )
            .await,
            &b"age-refiltered"[..]
        );
    }
}

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::config::{LimiterConfig, WindowLimit};
use crate::protocol::RateLimitKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitError {
    Exceeded {
        retry_after_secs: u64,
        kind: RateLimitKind,
    },
    Unavailable,
}

/// Post-signature per-npub request limiting. Per-source limiting belongs to
/// the test-pinned Nginx zones, which are the only rate boundary for requests
/// that never reach an npub window, such as signed fetches of absent heads.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<State>>,
    salt: [u8; 32],
    config: LimiterConfig,
}

#[derive(Default)]
struct State {
    fetch_by_npub: HashMap<[u8; 32], VecDeque<Instant>>,
    mutation_by_npub: HashMap<[u8; 32], VecDeque<Instant>>,
    fetch_overflow: VecDeque<Instant>,
    mutation_overflow: VecDeque<Instant>,
    last_full_prune: Option<Instant>,
    #[cfg(test)]
    full_prunes: usize,
}

impl State {
    fn prune_all_if_due(&mut self, config: &LimiterConfig, now: Instant) {
        if self.last_full_prune.is_some_and(|last| {
            now.checked_duration_since(last)
                .is_some_and(|elapsed| elapsed < config.prune_interval)
        }) {
            return;
        }
        self.last_full_prune = Some(now);
        prune_windows(&mut self.fetch_by_npub, config.fetch_npub.window, now);
        prune_windows(&mut self.mutation_by_npub, config.mutation_npub.window, now);
        prune_events(&mut self.fetch_overflow, config.overflow.window, now);
        prune_events(&mut self.mutation_overflow, config.overflow.window, now);
        #[cfg(test)]
        {
            self.full_prunes = self.full_prunes.saturating_add(1);
        }
    }
}

impl RateLimiter {
    pub fn new(config: LimiterConfig) -> Result<Self, String> {
        if config.max_subjects == 0
            || config.overflow_retry_after_secs == 0
            || config.prune_interval.is_zero()
            || [config.overflow, config.fetch_npub, config.mutation_npub]
                .iter()
                .any(|limit| limit.requests == 0 || limit.window.is_zero())
        {
            return Err("limiter values must be positive".to_owned());
        }
        let mut salt = [0_u8; 32];
        getrandom::fill(&mut salt).map_err(|_| "OS randomness unavailable".to_owned())?;
        Ok(Self {
            inner: Arc::new(Mutex::new(State::default())),
            salt,
            config,
        })
    }

    pub fn check_fetch_npub(&self, npub: &[u8; 32]) -> Result<(), LimitError> {
        let key = self.digest(b"fetch-npub", npub);
        self.check(key, Axis::Fetch)
    }

    pub fn check_mutation_npub(&self, npub: &[u8; 32]) -> Result<(), LimitError> {
        let key = self.digest(b"mutation-npub", npub);
        self.check(key, Axis::Mutation)
    }

    fn check(&self, key: [u8; 32], axis: Axis) -> Result<(), LimitError> {
        let mut state = self.inner.lock().map_err(|_| LimitError::Unavailable)?;
        let now = Instant::now();
        state.prune_all_if_due(&self.config, now);
        let State {
            fetch_by_npub,
            mutation_by_npub,
            fetch_overflow,
            mutation_overflow,
            ..
        } = &mut *state;
        let (map, overflow, limit) = match axis {
            Axis::Fetch => (fetch_by_npub, fetch_overflow, self.config.fetch_npub),
            Axis::Mutation => (
                mutation_by_npub,
                mutation_overflow,
                self.config.mutation_npub,
            ),
        };
        check_window(
            map,
            overflow,
            key,
            limit,
            self.config.overflow,
            self.config.max_subjects,
            self.config.overflow_retry_after_secs,
            now,
        )
    }

    fn digest(&self, label: &[u8], value: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(self.salt);
        digest.update(label);
        digest.update(value);
        digest.finalize().into()
    }
}

#[derive(Clone, Copy)]
enum Axis {
    Fetch,
    Mutation,
}

#[allow(clippy::too_many_arguments)]
fn check_window(
    map: &mut HashMap<[u8; 32], VecDeque<Instant>>,
    overflow: &mut VecDeque<Instant>,
    key: [u8; 32],
    limit: WindowLimit,
    overflow_limit: WindowLimit,
    max_subjects: usize,
    overflow_retry_after_secs: u64,
    now: Instant,
) -> Result<(), LimitError> {
    if let Some(events) = map.get_mut(&key) {
        prune_events(events, limit.window, now);
        if !events.is_empty() {
            return admit_event(events, limit, RateLimitKind::Npub, now);
        }
        map.remove(&key);
    }
    if map.len() < max_subjects {
        map.insert(key, VecDeque::from([now]));
        return Ok(());
    }
    prune_events(overflow, overflow_limit.window, now);
    match admit_event(overflow, overflow_limit, RateLimitKind::Overflow, now) {
        Err(LimitError::Exceeded { kind, .. }) => Err(LimitError::Exceeded {
            retry_after_secs: overflow_retry_after_secs,
            kind,
        }),
        result => result,
    }
}

fn admit_event(
    events: &mut VecDeque<Instant>,
    limit: WindowLimit,
    kind: RateLimitKind,
    now: Instant,
) -> Result<(), LimitError> {
    if events.len() >= limit.requests {
        let retry_after_secs = events
            .front()
            .and_then(|first| first.checked_add(limit.window))
            .and_then(|ready| ready.checked_duration_since(now))
            .map_or(1, ceil_seconds);
        return Err(LimitError::Exceeded {
            retry_after_secs,
            kind,
        });
    }
    events.push_back(now);
    Ok(())
}

fn ceil_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
        .max(1)
}

fn prune_windows(map: &mut HashMap<[u8; 32], VecDeque<Instant>>, window: Duration, now: Instant) {
    map.retain(|_, events| {
        prune_events(events, window, now);
        !events.is_empty()
    });
}

fn prune_events(events: &mut VecDeque<Instant>, window: Duration, now: Instant) {
    let cutoff = now.checked_sub(window).unwrap_or(now);
    while events.front().is_some_and(|event| *event < cutoff) {
        events.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(requests: usize, seconds: u64) -> WindowLimit {
        WindowLimit {
            requests,
            window: Duration::from_secs(seconds),
        }
    }

    fn config() -> LimiterConfig {
        LimiterConfig {
            max_subjects: 2,
            overflow: window(2, 60),
            overflow_retry_after_secs: 17,
            prune_interval: Duration::from_secs(60),
            fetch_npub: window(3, 60),
            mutation_npub: window(2, 60),
        }
    }

    #[test]
    fn each_axis_allows_exactly_its_configured_limit() -> Result<(), String> {
        let limiter = RateLimiter::new(config())?;
        for _ in 0..3 {
            limiter
                .check_fetch_npub(&[1; 32])
                .map_err(|error| format!("unexpected fetch npub result: {error:?}"))?;
        }
        assert!(matches!(
            limiter.check_fetch_npub(&[1; 32]),
            Err(LimitError::Exceeded {
                kind: RateLimitKind::Npub,
                ..
            })
        ));
        for _ in 0..2 {
            limiter
                .check_mutation_npub(&[1; 32])
                .map_err(|error| format!("unexpected mutation npub result: {error:?}"))?;
        }
        assert!(matches!(
            limiter.check_mutation_npub(&[1; 32]),
            Err(LimitError::Exceeded {
                kind: RateLimitKind::Npub,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn exact_window_boundary_remains_inclusive() -> Result<(), String> {
        let mut map = HashMap::new();
        let mut overflow = VecDeque::new();
        let first = Instant::now();
        let limit = window(1, 60);
        check_window(&mut map, &mut overflow, [1; 32], limit, limit, 1, 17, first)
            .map_err(|error| format!("unexpected first result: {error:?}"))?;
        assert!(
            check_window(
                &mut map,
                &mut overflow,
                [1; 32],
                limit,
                limit,
                1,
                17,
                first + limit.window,
            )
            .is_err()
        );
        check_window(
            &mut map,
            &mut overflow,
            [1; 32],
            limit,
            limit,
            1,
            17,
            first + limit.window + Duration::from_nanos(1),
        )
        .map_err(|error| format!("unexpected expired result: {error:?}"))?;
        Ok(())
    }

    #[test]
    fn full_map_uses_bounded_overflow_without_evicting_active_subjects() -> Result<(), String> {
        let mut map = HashMap::new();
        let mut overflow = VecDeque::new();
        let now = Instant::now();
        let subject_limit = window(2, 60);
        let overflow_limit = window(1, 60);
        check_window(
            &mut map,
            &mut overflow,
            [1; 32],
            subject_limit,
            overflow_limit,
            1,
            17,
            now,
        )
        .map_err(|error| format!("unexpected subject result: {error:?}"))?;
        check_window(
            &mut map,
            &mut overflow,
            [2; 32],
            subject_limit,
            overflow_limit,
            1,
            17,
            now,
        )
        .map_err(|error| format!("unexpected overflow result: {error:?}"))?;
        assert_eq!(
            check_window(
                &mut map,
                &mut overflow,
                [3; 32],
                subject_limit,
                overflow_limit,
                1,
                17,
                now,
            ),
            Err(LimitError::Exceeded {
                retry_after_secs: 17,
                kind: RateLimitKind::Overflow,
            })
        );
        assert!(map.contains_key(&[1; 32]));
        assert!(!map.contains_key(&[2; 32]));
        Ok(())
    }

    #[test]
    fn full_pruning_is_bounded_by_configured_interval() -> Result<(), String> {
        let config = config();
        let mut state = State::default();
        let now = Instant::now();
        let expired = now
            .checked_sub(config.fetch_npub.window + Duration::from_secs(1))
            .ok_or_else(|| "test instant underflow".to_owned())?;
        state.prune_all_if_due(&config, now);
        state
            .fetch_by_npub
            .insert([1; 32], VecDeque::from([expired]));
        let before_prune = (now + config.prune_interval)
            .checked_sub(Duration::from_nanos(1))
            .ok_or_else(|| "test instant underflow".to_owned())?;
        state.prune_all_if_due(&config, before_prune);
        assert_eq!(state.full_prunes, 1);
        assert!(state.fetch_by_npub.contains_key(&[1; 32]));
        state.prune_all_if_due(&config, now + config.prune_interval);
        assert_eq!(state.full_prunes, 2);
        assert!(state.fetch_by_npub.is_empty());
        Ok(())
    }

    #[test]
    fn overflow_allowances_are_isolated_by_axis() -> Result<(), String> {
        let mut policy = config();
        policy.max_subjects = 1;
        policy.overflow = window(1, 60);
        let limiter = RateLimiter::new(policy)?;

        limiter
            .check_fetch_npub(&[1; 32])
            .map_err(|error| format!("fetch npub map failed: {error:?}"))?;
        limiter
            .check_fetch_npub(&[2; 32])
            .map_err(|error| format!("fetch npub overflow failed: {error:?}"))?;

        limiter
            .check_mutation_npub(&[1; 32])
            .map_err(|error| format!("mutation npub map failed: {error:?}"))?;
        limiter
            .check_mutation_npub(&[2; 32])
            .map_err(|error| format!("mutation npub overflow failed: {error:?}"))?;

        assert!(limiter.check_fetch_npub(&[3; 32]).is_err());
        assert!(limiter.check_mutation_npub(&[3; 32]).is_err());
        Ok(())
    }

    #[test]
    fn concurrent_checks_cannot_overshoot() -> Result<(), String> {
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicUsize, Ordering};

        const THREADS: usize = 16;
        let mut policy = config();
        policy.fetch_npub = window(10, 60);
        let limiter = RateLimiter::new(policy)?;
        let barrier = Arc::new(Barrier::new(THREADS));
        let allowed = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                let limiter = limiter.clone();
                let barrier = Arc::clone(&barrier);
                let allowed = Arc::clone(&allowed);
                scope.spawn(move || {
                    barrier.wait();
                    if limiter.check_fetch_npub(&[9; 32]).is_ok() {
                        allowed.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(allowed.load(Ordering::Relaxed), 10);
        Ok(())
    }
}

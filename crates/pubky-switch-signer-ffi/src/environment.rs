//! The signer's authenticated Homeserver, clock and restricted HTTP transport (Switch spec 4.1).

use crate::{SignerFfiError, protocol};
use pubky_switch_client::clock::SystemClock;
use pubky_switch_client::store::{MAX_VALUE_BYTES, StoreHandle};
use pubky_switch_client::transport::{BoxFuture, HttpConfig, HttpTransport, TransportError};
use pubky_switch_signer::{Homeserver, Protocols, SignerEnv};
use std::sync::Arc;
use std::time::Duration;

/// Why the host could not confirm a Homeserver operation (Switch spec 4.1).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum HomeserverFailure {
    /// No connection could be made, so nothing was sent (Switch spec 4.1).
    #[error("homeserver unreachable")]
    Unreachable,
    /// The host's deadline passed (Switch spec 4.1).
    #[error("homeserver deadline passed")]
    Timeout,
    /// The Homeserver refused the session's access to the path, as with a `401` or a `403`:
    /// the file is unchanged (Switch wire 3.13).
    #[error("homeserver access denied")]
    Denied,
    /// The file is larger than the limit `get` gave. A read stops at the limit and returns
    /// this instead of the bytes (Switch wire 3.13).
    #[error("homeserver file exceeds byte limit")]
    TooLarge {
        /// The limit the file exceeds, in bytes (Switch wire 3.13).
        limit: u64,
    },
    /// The host could not establish the outcome (Switch spec 4.1).
    #[error("homeserver operation failed")]
    Other,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for HomeserverFailure {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Other
    }
}

impl From<HomeserverFailure> for TransportError {
    fn from(error: HomeserverFailure) -> Self {
        match error {
            HomeserverFailure::Unreachable => Self::Connect("homeserver connection".into()),
            HomeserverFailure::Timeout => Self::Timeout,
            HomeserverFailure::Denied => Self::Refused("homeserver access".into()),
            HomeserverFailure::TooLarge { limit } => Self::TooLarge(limit),
            HomeserverFailure::Other => Self::Other("homeserver operation".into()),
        }
    }
}

/// Access the identity's files with its authenticated session. Files are at most 16 MiB, the
/// signer's local value limit, which its largest backup fits (Switch wire 3.13). Report every
/// failure as a [`HomeserverFailure`]: another exception's text is dropped, and an error a
/// Kotlin callback throws that isn't an `Exception` leaves the call unanswered.
///
/// Each call has a deadline, the long timeout of the environment's [`TransportOptions`]. A
/// call past it fails as a timeout, which for `put` and `delete` leaves the outcome unknown.
/// An answer that comes after the deadline is dropped; the bytes it carries are not freed, a
/// small leak on that path only.
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait HostHomeserver: Send + Sync {
    /// Return None only for a confirmed absence. Throw if absence and denial cannot be
    /// distinguished, or if the read otherwise fails. Read at most `limit` bytes: stop reading
    /// past it and throw [`HomeserverFailure::TooLarge`] without returning the bytes, which
    /// would be copied in full before the signer could refuse them (Switch wire 3.13).
    async fn get(&self, path: String, limit: u64) -> Result<Option<Vec<u8>>, HomeserverFailure>;
    /// Confirm an accepted write. The signer may send the same bytes again (Switch wire 3.13).
    async fn put(&self, path: String, bytes: Vec<u8>) -> Result<(), HomeserverFailure>;
    /// Delete the file. Deleting an absent file succeeds (Switch spec 12.7).
    async fn delete(&self, path: String) -> Result<(), HomeserverFailure>;
}

/// The host's session, each call bounded by `deadline`.
struct Session {
    host: Arc<dyn HostHomeserver>,
    deadline: Duration,
}

impl Session {
    /// Wait for the host's answer until the deadline: a host that never answers would hold
    /// the signer's call, and the store's lock with it, without end.
    async fn answer<T>(
        &self,
        call: impl std::future::Future<Output = Result<T, HomeserverFailure>>,
    ) -> Result<T, TransportError> {
        match tokio::time::timeout(self.deadline, call).await {
            Ok(answer) => Ok(answer?),
            Err(_) => Err(TransportError::Timeout),
        }
    }
}

/// Bound each transfer of a signer file, including the backup (Switch wire 3.13).
pub(crate) fn check_file_size(len: usize) -> Result<(), TransportError> {
    if u64::try_from(len).is_ok_and(|bytes| bytes <= MAX_VALUE_BYTES) {
        Ok(())
    } else {
        Err(TransportError::TooLarge(MAX_VALUE_BYTES))
    }
}

impl Homeserver for Session {
    fn get(&self, path: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        let call = self.host.get(path.to_owned(), MAX_VALUE_BYTES);
        Box::pin(async move {
            // The host stops at the limit; a file over it is refused here all the same.
            let file = self.answer(call).await?;
            if let Some(bytes) = &file {
                check_file_size(bytes.len())?;
            }
            Ok(file)
        })
    }

    fn put(&self, path: &str, bytes: Vec<u8>) -> BoxFuture<'_, Result<(), TransportError>> {
        let path = path.to_owned();
        Box::pin(async move {
            check_file_size(bytes.len())?;
            self.answer(self.host.put(path, bytes)).await
        })
    }

    fn delete(&self, path: &str) -> BoxFuture<'_, Result<(), TransportError>> {
        let call = self.host.delete(path.to_owned());
        Box::pin(async move { self.answer(call).await })
    }
}

/// Adapt the host's authenticated session to signer file operations, each bounded by the
/// long timeout of `config` (Switch spec 4.1).
pub(crate) fn session(host: Arc<dyn HostHomeserver>, config: &HttpConfig) -> Arc<dyn Homeserver> {
    Arc::new(Session {
        host,
        deadline: Duration::from_millis(config.long_timeout_ms),
    })
}

/// The longest timeout a host may set, in milliseconds: 10 minutes. A slow network raises
/// the timeouts toward it; a longer one would hold a signer call open past any use.
pub const MAX_TIMEOUT_MS: u64 = 10 * 60 * 1000;

/// The largest answer body a host may allow, in bytes: 256 MiB. The client's default, 33
/// MiB, holds the largest peer list at the service's default limits (Switch wire 9.3); a
/// service with higher limits needs more, and the bound keeps a read's memory finite.
pub const MAX_RESPONSE_BYTES: u64 = 256 << 20;

/// HTTP limits, each at least 1 and at most its maximum: 600,000 milliseconds (10 minutes) for
/// a timeout, and 268,435,456 bytes (256 MiB) for the response bound. A value out of range is
/// refused, naming its field. Omitted fields keep the client's defaults (Switch wire 7.1).
#[derive(Default, uniffi::Record)]
pub struct TransportOptions {
    /// Small request timeout in milliseconds (Switch wire 7.1).
    #[uniffi(default = None)]
    pub request_timeout_ms: Option<u64>,
    /// Bulk transfer timeout in milliseconds, also each Homeserver call's deadline (Switch
    /// wire 7.1).
    #[uniffi(default = None)]
    pub long_timeout_ms: Option<u64>,
    /// Connection timeout in milliseconds (Switch wire 7.1).
    #[uniffi(default = None)]
    pub connect_timeout_ms: Option<u64>,
    /// Upper bound on response bytes (Switch wire 7.1).
    #[uniffi(default = None)]
    pub max_response_bytes: Option<u64>,
}

impl TransportOptions {
    fn config(self) -> Result<HttpConfig, SignerFfiError> {
        let mut config = HttpConfig::default();
        // A value out of range is refused, naming the field: never clamped.
        macro_rules! apply {
            ($field:ident, $max:expr) => {
                match self.$field {
                    Some(value) if value == 0 || value > $max => {
                        return Err(SignerFfiError::InvalidInput {
                            reason: stringify!($field).into(),
                        })
                    }
                    Some(value) => config.$field = value,
                    None => {}
                }
            };
        }
        apply!(request_timeout_ms, MAX_TIMEOUT_MS);
        apply!(long_timeout_ms, MAX_TIMEOUT_MS);
        apply!(connect_timeout_ms, MAX_TIMEOUT_MS);
        apply!(max_response_bytes, MAX_RESPONSE_BYTES);
        Ok(config)
    }
}

/// The session and Rust-owned services shared by a signer (Switch spec 4.1). It holds the
/// host's Homeserver object until the environment itself is closed, not when a signer is.
#[derive(uniffi::Object)]
pub struct SignerEnvironment {
    homeserver: Arc<dyn Homeserver>,
    transport: Arc<HttpTransport>,
    protocols: Protocols,
    /// The limits the transport and the session were built with, for tests to compare.
    #[cfg(test)]
    config: HttpConfig,
}

#[uniffi::export]
impl SignerEnvironment {
    /// Use the registered protocols, system clock and checked HTTP origins (Switch wire 7.1).
    #[uniffi::constructor]
    pub fn new(
        homeserver: Box<dyn HostHomeserver>,
        transport: TransportOptions,
    ) -> Result<Arc<Self>, SignerFfiError> {
        let config = transport.config()?;
        let protocols = protocol::registered()?;
        let transport =
            HttpTransport::new(config.clone()).map_err(pubky_switch_client::ClientError::from)?;
        Ok(Arc::new(Self {
            homeserver: session(Arc::from(homeserver), &config),
            transport: Arc::new(transport),
            protocols,
            #[cfg(test)]
            config,
        }))
    }
}

impl SignerEnvironment {
    /// Pair this environment with the store holding the signer's records (Switch wire 2.1).
    // Used when opening a signer.
    #[allow(dead_code)]
    pub(crate) fn signer_env(&self, store: StoreHandle) -> SignerEnv {
        SignerEnv {
            store,
            clock: Arc::new(SystemClock),
            transport: self.transport.clone(),
            homeserver: self.homeserver.clone(),
            protocols: self.protocols.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransportFailure;
    use pubky_switch_client::store::MemoryStore;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemoryHome {
        files: Mutex<BTreeMap<String, Vec<u8>>>,
        /// The limit each read was given.
        limits: Mutex<Vec<u64>>,
        denied: bool,
        unreachable: bool,
        failing_writes: bool,
        never_answers: bool,
    }

    #[async_trait::async_trait]
    impl HostHomeserver for MemoryHome {
        async fn get(
            &self,
            path: String,
            limit: u64,
        ) -> Result<Option<Vec<u8>>, HomeserverFailure> {
            self.limits.lock().unwrap().push(limit);
            if self.never_answers {
                std::future::pending::<()>().await;
            }
            if self.denied {
                return Err(HomeserverFailure::Denied);
            }
            if self.unreachable {
                return Err(HomeserverFailure::Unreachable);
            }
            let file = self.files.lock().unwrap().get(&path).cloned();
            if file
                .as_ref()
                .is_some_and(|bytes| bytes.len() as u64 > limit)
            {
                return Err(HomeserverFailure::TooLarge { limit });
            }
            Ok(file)
        }

        async fn put(&self, path: String, bytes: Vec<u8>) -> Result<(), HomeserverFailure> {
            if self.never_answers {
                std::future::pending::<()>().await;
            }
            if self.failing_writes {
                return Err(HomeserverFailure::Other);
            }
            self.files.lock().unwrap().insert(path, bytes);
            Ok(())
        }

        async fn delete(&self, path: String) -> Result<(), HomeserverFailure> {
            if self.never_answers {
                std::future::pending::<()>().await;
            }
            if self.failing_writes {
                return Err(HomeserverFailure::Other);
            }
            self.files.lock().unwrap().remove(&path);
            Ok(())
        }
    }

    // A host handle the test keeps while the bindings own the box.
    #[async_trait::async_trait]
    impl HostHomeserver for Arc<MemoryHome> {
        async fn get(
            &self,
            path: String,
            limit: u64,
        ) -> Result<Option<Vec<u8>>, HomeserverFailure> {
            self.as_ref().get(path, limit).await
        }

        async fn put(&self, path: String, bytes: Vec<u8>) -> Result<(), HomeserverFailure> {
            self.as_ref().put(path, bytes).await
        }

        async fn delete(&self, path: String) -> Result<(), HomeserverFailure> {
            self.as_ref().delete(path).await
        }
    }

    #[tokio::test]
    async fn test_environment_round_trip() {
        protocol::sample().unwrap();
        let host = Arc::new(MemoryHome::default());
        let environment =
            SignerEnvironment::new(Box::new(host.clone()), TransportOptions::default()).unwrap();
        let store = StoreHandle::new(Arc::new(MemoryStore::new()));
        let env = environment.signer_env(store.clone());
        assert!(Arc::ptr_eq(env.store.store(), store.store()));
        assert!(env.clock.now_ms() > 0);
        assert_eq!(env.protocols.names(), ["sample"]);
        let path = "/sample";
        assert_eq!(env.homeserver.get(path).await.unwrap(), None);
        for _ in 0..2 {
            env.homeserver.put(path, vec![0, 255, 1]).await.unwrap();
            assert!(
                host.files
                    .lock()
                    .unwrap()
                    .get(path)
                    .is_some_and(|v| v == &[0, 255, 1])
            );
        }
        assert_eq!(
            env.homeserver.get(path).await.unwrap(),
            Some(vec![0, 255, 1])
        );
        env.homeserver.delete(path).await.unwrap();
        env.homeserver.delete(path).await.unwrap();
        assert_eq!(env.homeserver.get(path).await.unwrap(), None);
        // Every read carried the signer's 16 MiB file limit.
        let limits = host.limits.lock().unwrap().clone();
        assert_eq!(limits, [16 << 20; 3]);
    }

    #[tokio::test]
    async fn test_environment_failed_writes() {
        let home = session(
            Arc::new(MemoryHome {
                failing_writes: true,
                ..Default::default()
            }),
            &HttpConfig::default(),
        );
        assert!(matches!(
            home.put("/sample", vec![1]).await,
            Err(TransportError::Other(_))
        ));
        assert!(matches!(
            home.delete("/sample").await,
            Err(TransportError::Other(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn test_environment_uses_the_hosts_options() {
        protocol::sample().unwrap();
        let options = || TransportOptions {
            request_timeout_ms: Some(12),
            long_timeout_ms: Some(50),
            connect_timeout_ms: Some(16),
            max_response_bytes: Some(18),
        };
        let host = MemoryHome {
            never_answers: true,
            ..Default::default()
        };
        let environment = SignerEnvironment::new(Box::new(host), options()).unwrap();
        assert_eq!(environment.config, options().config().unwrap());
        // A host that never answers fails at the long timeout, as a timeout.
        let env = environment.signer_env(StoreHandle::new(Arc::new(MemoryStore::new())));
        let started = tokio::time::Instant::now();
        let calls: [BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>>; 3] = [
            env.homeserver.get("/sample"),
            Box::pin(async { env.homeserver.put("/sample", vec![1]).await.map(|()| None) }),
            Box::pin(async { env.homeserver.delete("/sample").await.map(|()| None) }),
        ];
        for call in calls {
            assert!(matches!(call.await, Err(TransportError::Timeout)));
        }
        assert_eq!(started.elapsed(), Duration::from_millis(150));
    }

    #[tokio::test]
    async fn test_environment_failed_read() {
        let denied = session(
            Arc::new(MemoryHome {
                denied: true,
                ..Default::default()
            }),
            &HttpConfig::default(),
        );
        assert!(matches!(
            denied.get("/missing").await,
            Err(TransportError::Refused(_))
        ));
        let offline = session(
            Arc::new(MemoryHome {
                unreachable: true,
                ..Default::default()
            }),
            &HttpConfig::default(),
        );
        assert!(matches!(
            offline.get("/missing").await,
            Err(TransportError::Connect(_))
        ));
    }

    #[test]
    fn test_environment_callback_errors() {
        let marker = "private callback text";
        let unexpected = uniffi::UnexpectedUniFFICallbackError::new(marker);
        for (source, expected, bytes) in [
            (
                HomeserverFailure::Unreachable,
                TransportFailure::Connect,
                None,
            ),
            (HomeserverFailure::Denied, TransportFailure::Refused, None),
            (HomeserverFailure::Timeout, TransportFailure::Timeout, None),
            (
                HomeserverFailure::TooLarge { limit: 20 },
                TransportFailure::TooLarge,
                Some(20),
            ),
            (HomeserverFailure::Other, TransportFailure::Other, None),
            (unexpected.into(), TransportFailure::Other, None),
        ] {
            let transport = TransportError::from(source);
            assert!(!transport.to_string().contains(marker));
            assert!(!format!("{transport:?}").contains(marker));
            let error =
                SignerFfiError::from(pubky_switch_signer::SignerError::Homeserver(transport));
            assert!(
                matches!(error, SignerFfiError::Homeserver { kind, size, status: None } if kind == expected && size == bytes)
            );
        }
    }

    #[tokio::test]
    async fn test_environment_file_size() {
        let limit = usize::try_from(MAX_VALUE_BYTES).unwrap();
        assert!(check_file_size(limit).is_ok());
        let host = Arc::new(MemoryHome::default());
        let home = session(host.clone(), &HttpConfig::default());
        let path = "/sample";
        assert!(matches!(
            home.put(path, vec![0; limit + 1]).await,
            Err(TransportError::TooLarge(MAX_VALUE_BYTES))
        ));
        assert!(host.files.lock().unwrap().is_empty());
        host.files
            .lock()
            .unwrap()
            .insert(path.into(), vec![0; limit + 1]);
        assert!(matches!(
            home.get(path).await,
            Err(TransportError::TooLarge(MAX_VALUE_BYTES))
        ));
    }

    #[test]
    fn test_environment_http_options() {
        assert_eq!(
            TransportOptions::default().config().unwrap(),
            HttpConfig::default()
        );
        let config = TransportOptions {
            request_timeout_ms: Some(12),
            long_timeout_ms: Some(14),
            connect_timeout_ms: Some(16),
            max_response_bytes: Some(18),
        }
        .config()
        .unwrap();
        assert_eq!(
            (
                config.request_timeout_ms,
                config.long_timeout_ms,
                config.connect_timeout_ms,
                config.max_response_bytes
            ),
            (12, 14, 16, 18)
        );
        assert!(config.extra_ports.is_empty());
    }

    #[cfg(feature = "test-fixtures")]
    #[tokio::test]
    async fn test_environment_host_fixtures() {
        use crate::{
            SampleFailure, homeserver_round_trip, register_sample_protocol, sample_failure,
        };
        register_sample_protocol().unwrap();
        assert_eq!(crate::protocol_names().unwrap(), ["sample"]);
        assert!(matches!(sample_failure(SampleFailure::NotNamed),
            Err(SignerFfiError::NotNamed { install }) if install == [5; 16]));
        let host = Arc::new(MemoryHome::default());
        let trip = homeserver_round_trip(Box::new(host.clone()), "/sample".into(), vec![255, 0])
            .await
            .unwrap();
        assert!(trip.absent_before && trip.matched_after_put && trip.absent_after);
        assert!(host.files.lock().unwrap().is_empty());
        // A file over the limit is refused before the host is called.
        let over = vec![0; usize::try_from(MAX_VALUE_BYTES).unwrap() + 1];
        assert!(matches!(
            homeserver_round_trip(Box::new(host.clone()), "/sample".into(), over).await,
            Err(SignerFfiError::Homeserver {
                kind: crate::TransportFailure::TooLarge,
                size: Some(MAX_VALUE_BYTES),
                ..
            })
        ));
        assert_eq!(
            host.limits.lock().unwrap().len(),
            3,
            "no call for the refused file"
        );
        host.put("/sample".into(), vec![4]).await.unwrap();
        assert!(matches!(
            homeserver_round_trip(Box::new(host.clone()), "/sample".into(), vec![]).await,
            Err(SignerFfiError::InvalidInput { .. })
        ));
        assert_eq!(
            host.get("/sample".into(), MAX_VALUE_BYTES).await.unwrap(),
            Some(vec![4])
        );
    }

    #[test]
    fn test_environment_limits_out_of_range() {
        protocol::sample().unwrap();
        for (value, top) in [(0, false), (MAX_TIMEOUT_MS + 1, true), (u64::MAX, true)] {
            let cases = [
                (
                    "request_timeout_ms",
                    TransportOptions {
                        request_timeout_ms: Some(value),
                        ..Default::default()
                    },
                ),
                (
                    "long_timeout_ms",
                    TransportOptions {
                        long_timeout_ms: Some(value),
                        ..Default::default()
                    },
                ),
                (
                    "connect_timeout_ms",
                    TransportOptions {
                        connect_timeout_ms: Some(value),
                        ..Default::default()
                    },
                ),
            ];
            for (name, options) in cases {
                assert!(
                    matches!(SignerEnvironment::new(Box::new(MemoryHome::default()), options), Err(SignerFfiError::InvalidInput { reason }) if reason == name),
                    "{name} {value} {top}"
                );
            }
        }
        for value in [MAX_RESPONSE_BYTES + 1, u64::MAX] {
            let options = TransportOptions {
                max_response_bytes: Some(value),
                ..Default::default()
            };
            assert!(
                matches!(SignerEnvironment::new(Box::new(MemoryHome::default()), options), Err(SignerFfiError::InvalidInput { reason }) if reason == "max_response_bytes")
            );
        }
        // The maximums themselves are taken.
        let config = TransportOptions {
            request_timeout_ms: Some(MAX_TIMEOUT_MS),
            long_timeout_ms: Some(MAX_TIMEOUT_MS),
            connect_timeout_ms: Some(MAX_TIMEOUT_MS),
            max_response_bytes: Some(MAX_RESPONSE_BYTES),
        }
        .config()
        .unwrap();
        assert_eq!(
            (
                config.request_timeout_ms,
                config.long_timeout_ms,
                config.connect_timeout_ms,
                config.max_response_bytes
            ),
            (
                MAX_TIMEOUT_MS,
                MAX_TIMEOUT_MS,
                MAX_TIMEOUT_MS,
                MAX_RESPONSE_BYTES
            )
        );
        assert_eq!((MAX_TIMEOUT_MS, MAX_RESPONSE_BYTES), (600_000, 256 << 20));
    }

    #[test]
    fn test_environment_zero_limits() {
        protocol::sample().unwrap();
        for (name, options) in [
            (
                "request_timeout_ms",
                TransportOptions {
                    request_timeout_ms: Some(0),
                    ..Default::default()
                },
            ),
            (
                "long_timeout_ms",
                TransportOptions {
                    long_timeout_ms: Some(0),
                    ..Default::default()
                },
            ),
            (
                "connect_timeout_ms",
                TransportOptions {
                    connect_timeout_ms: Some(0),
                    ..Default::default()
                },
            ),
            (
                "max_response_bytes",
                TransportOptions {
                    max_response_bytes: Some(0),
                    ..Default::default()
                },
            ),
        ] {
            assert!(
                matches!(SignerEnvironment::new(Box::new(MemoryHome::default()), options), Err(SignerFfiError::InvalidInput { reason }) if reason == name)
            );
        }
    }
}

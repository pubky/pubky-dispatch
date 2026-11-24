//! The protocols a signer build registers and the authority their scopes confer (Switch spec 3.2).

use crate::{ProtocolFailure, SignerFfiError};
use pubky_switch_signer::{Protocol, ProtocolError, Protocols};
use std::sync::{Arc, OnceLock};

static REGISTRY: OnceLock<Protocols> = OnceLock::new();

/// Install the build's protocol rules once, before serving host calls (Switch spec 3.2).
pub fn register_protocols(protocols: Vec<Arc<dyn Protocol>>) -> Result<(), SignerFfiError> {
    register_into(&REGISTRY, protocols)
}

fn register_into(
    registry: &OnceLock<Protocols>,
    protocols: Vec<Arc<dyn Protocol>>,
) -> Result<(), SignerFfiError> {
    let already = || SignerFfiError::Protocols {
        kind: ProtocolFailure::AlreadyRegistered,
    };
    // A second registration is refused as one, whatever the set it brings.
    if registry.get().is_some() {
        return Err(already());
    }
    let set = Protocols::new(protocols)?;
    registry.set(set).map_err(|_| already())
}

fn read_registry(registry: &OnceLock<Protocols>) -> Result<&Protocols, SignerFfiError> {
    registry
        .get()
        .ok_or_else(|| ProtocolError::NoProtocols.into())
}

/// The same protocol rules are used throughout the signer's life (Switch spec 3.2).
pub(crate) fn registered() -> Result<Protocols, SignerFfiError> {
    read_registry(&REGISTRY).cloned()
}

/// Read the registered names in declaration order (Switch wire 3.1).
#[uniffi::export]
pub fn protocol_names() -> Result<Vec<String>, SignerFfiError> {
    Ok(read_registry(&REGISTRY)?
        .names()
        .into_iter()
        .map(str::to_owned)
        .collect())
}

/// The authority to display for an approval or renewal (Switch spec 3.2).
#[derive(uniffi::Record)]
pub struct ScopeTerms {
    /// Switch permissions in certificate order (Switch wire 3.1).
    pub permissions: Vec<String>,
    /// Requested scopes with Shared Data Keys, in request order (Switch spec 3.5).
    pub keyed: Vec<String>,
}

/// Apply the Switch and protocol rules to the requested scopes (Switch wire 3.9).
#[uniffi::export]
pub fn scope_terms(scopes: Vec<String>) -> Result<ScopeTerms, SignerFfiError> {
    let terms = read_registry(&REGISTRY)?.terms(&scopes)?;
    Ok(ScopeTerms {
        permissions: terms.permission_names(),
        keyed: terms.keyed,
    })
}

#[cfg(all(test, not(feature = "test-fixtures")))]
#[path = "environment_fixtures.rs"]
mod sample_support;
#[cfg(all(test, feature = "test-fixtures"))]
pub(crate) use crate::environment_fixtures::{Sample, register_sample_protocol as sample};
#[cfg(all(test, not(feature = "test-fixtures")))]
pub(crate) use sample_support::{Sample, register_sample_protocol as sample};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RefusalKind;

    #[test]
    fn test_protocol_unregistered() {
        assert!(matches!(
            read_registry(&OnceLock::new()),
            Err(SignerFfiError::Protocols {
                kind: ProtocolFailure::NoProtocols
            })
        ));
    }

    #[test]
    fn test_protocol_registration_once() {
        let registry = OnceLock::new();
        let refused = |protocols, expected| matches!(register_into(&registry, protocols), Err(SignerFfiError::Protocols { kind }) if kind == expected);
        assert!(refused(vec![], ProtocolFailure::NoProtocols));
        register_into(&registry, vec![Arc::new(Sample)]).unwrap();
        assert!(refused(vec![], ProtocolFailure::AlreadyRegistered));
        assert!(refused(
            vec![Arc::new(Sample)],
            ProtocolFailure::AlreadyRegistered
        ));
        assert_eq!(read_registry(&registry).unwrap().names(), ["sample"]);
    }

    #[test]
    fn test_protocol_registration() {
        sample().unwrap();
        sample().unwrap();
        assert!(matches!(
            register_protocols(vec![Arc::new(Sample)]),
            Err(SignerFfiError::Protocols {
                kind: ProtocolFailure::AlreadyRegistered
            })
        ));
        assert_eq!(protocol_names().unwrap(), ["sample"]);
    }

    #[test]
    fn test_protocol_refused_scope_names_stay_out_of_the_text() {
        sample().unwrap();
        let named = "elsewhere:sentinel-scope-label";
        let Err(error) = scope_terms(vec![named.into()]) else {
            panic!("expected a refusal")
        };
        let SignerFfiError::Refused {
            kind: RefusalKind::UnknownScopes,
            scopes: Some(scopes),
            ..
        } = &error
        else {
            panic!("expected unknown scopes")
        };
        assert_eq!(scopes.names, [named]);
        assert!(!error.to_string().contains("sentinel-scope-label"));
        assert!(!format!("{error:?}").contains("sentinel-scope-label"));
    }

    #[test]
    fn test_protocol_scope_terms() {
        sample().unwrap();
        let terms = scope_terms(vec!["sample-b".into(), "sample-a".into()]).unwrap();
        assert_eq!(terms.keyed, ["sample-a"]);
        assert_eq!(terms.permissions, ["claims.read", "lists.read"]);
    }

    #[test]
    fn test_protocol_refused_scopes() {
        sample().unwrap();
        for (scope, expected) in [
            ("unknown", RefusalKind::UnknownScopes),
            ("elsewhere:private-label", RefusalKind::UnknownScopes),
            ("sample-b", RefusalKind::ProtocolRule),
            ("", RefusalKind::Scopes),
        ] {
            assert!(
                matches!(scope_terms(vec![scope.into()]), Err(SignerFfiError::Refused {
                kind, ..
            }) if kind == expected)
            );
        }
    }
}

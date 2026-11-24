//! Check for public signer enum variants missing from the host guide and references to
//! variants those enums do not define.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../../tests/support/guide_enums.rs"]
mod guide_enums;

use guide_enums::{public_enums, rust_files};
use std::path::Path;

/// The guide.
const GUIDE: &str = include_str!("../../../docs/signer-host-guide.md");

/// Every source file of the crate but its test-only modules, by path, so that a public enum
/// in any of them is seen.
const SOURCES: &[(&str, &str)] = &[
    ("lib.rs", include_str!("../src/lib.rs")),
    ("alert.rs", include_str!("../src/alert.rs")),
    ("counters.rs", include_str!("../src/counters.rs")),
    ("error.rs", include_str!("../src/error.rs")),
    ("homeserver.rs", include_str!("../src/homeserver.rs")),
    ("key.rs", include_str!("../src/key.rs")),
    ("protocol.rs", include_str!("../src/protocol.rs")),
    ("state.rs", include_str!("../src/state.rs")),
    ("signer.rs", include_str!("../src/signer.rs")),
    (
        "signer/approval.rs",
        include_str!("../src/signer/approval.rs"),
    ),
    ("signer/apps.rs", include_str!("../src/signer/apps.rs")),
    (
        "signer/clients.rs",
        include_str!("../src/signer/clients.rs"),
    ),
    (
        "signer/erasure.rs",
        include_str!("../src/signer/erasure.rs"),
    ),
    ("signer/gate.rs", include_str!("../src/signer/gate.rs")),
    (
        "signer/handover.rs",
        include_str!("../src/signer/handover.rs"),
    ),
    (
        "signer/key_recovery.rs",
        include_str!("../src/signer/key_recovery.rs"),
    ),
    (
        "signer/recovery.rs",
        include_str!("../src/signer/recovery.rs"),
    ),
    (
        "signer/renewal.rs",
        include_str!("../src/signer/renewal.rs"),
    ),
    (
        "signer/restore.rs",
        include_str!("../src/signer/restore.rs"),
    ),
    (
        "signer/revocation.rs",
        include_str!("../src/signer/revocation.rs"),
    ),
    (
        "signer/takeover.rs",
        include_str!("../src/signer/takeover.rs"),
    ),
];

/// The source files compiled only under `cfg(test)`, by path under `src`: a public enum in one
/// of them is never shown to a host, so `SOURCES` needn't hold them.
const TEST_ONLY: &[&str] = &[
    // `#[cfg(test)] mod vector_cases;` in `signer.rs`.
    "signer/vector_cases.rs",
];

/// The public enums the guide covers: the alerts, statuses, errors, refusals, skip reasons,
/// sources, outcomes and standings a host receives or returns.
const COVERED: &[&str] = &[
    "Alert",
    "Source",
    "RenewalSkip",
    "FirstEnrollmentStop",
    "SignerError",
    "RecordsFault",
    "SignerRecord",
    "Refusal",
    "Counter",
    "SizedBody",
    "KeyError",
    "AddOutcome",
    "ExportReason",
    "ProtocolError",
    "SignerStatus",
    "AppStanding",
    "AbortOutcome",
    "KeyRecoveryStop",
    "AppFate",
    "BackupFound",
    "KeyRecoveryKind",
];

/// Public enums a host never receives or returns, so the guide needn't name their variants.
/// Each entry says why. Empty: every public enum of the crate is shown to a host.
const NOT_SHOWN: &[&str] = &[];

/// The declarations the signer guide requires, excluding any listed as never shown.
fn covered_enums() -> Vec<(String, Vec<String>)> {
    let mut enums = Vec::new();
    for (path, source) in SOURCES {
        for (name, variants) in public_enums(source) {
            if NOT_SHOWN.contains(&name.as_str()) {
                continue;
            }
            assert!(
                COVERED.contains(&name.as_str()),
                "{path} holds `pub enum {name}`, which is neither covered by the host guide \
                 nor listed as not shown to a host"
            );
            assert!(!variants.is_empty(), "`{name}` has no variants");
            enums.push((name, variants));
        }
    }
    for name in COVERED {
        assert!(
            enums.iter().any(|(declared, _)| declared == name),
            "no source holds `pub enum {name}`"
        );
    }
    enums
}

/// The `Name::Variant` pairs of `enums` that `guide` doesn't name in backticks.
fn missing_variants(guide: &str, enums: &[(String, Vec<String>)]) -> Vec<String> {
    enums
        .iter()
        .flat_map(|(name, variants)| variants.iter().map(move |v| format!("{name}::{v}")))
        .filter(|path| !guide.contains(&format!("`{path}`")))
        .collect()
}

/// The `Name::Variant` paths `guide` names in backticks whose `Name` is one of `enums` and
/// whose variant it doesn't have.
fn unknown_variants(guide: &str, enums: &[(String, Vec<String>)]) -> Vec<String> {
    let mut unknown = Vec::new();
    for (i, span) in guide.split('`').enumerate() {
        // The odd pieces are the insides of backtick spans.
        if i % 2 == 0 {
            continue;
        }
        let Some((name, rest)) = span.split_once("::") else {
            continue;
        };
        let variant: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if let Some((_, variants)) = enums.iter().find(|(n, _)| n == name)
            && !variants.contains(&variant)
        {
            unknown.push(format!("{name}::{variant}"));
        }
    }
    unknown
}

#[test]
fn test_host_guide_names_every_variant() {
    let missing = missing_variants(GUIDE, &covered_enums());
    assert!(
        missing.is_empty(),
        "the host guide doesn't name these variants: {missing:?}"
    );
}

#[test]
fn test_host_guide_status_checklist_names_every_status() {
    let (_, section) = GUIDE
        .split_once("### 3.12 Signer status\n")
        .expect("signer status checklist");
    let checklist = section.split("\n#").next().unwrap();
    let status = covered_enums()
        .into_iter()
        .find(|(name, _)| name == "SignerStatus")
        .expect("public SignerStatus");
    let missing = missing_variants(checklist, &[status]);
    assert!(
        missing.is_empty(),
        "statuses missing from checklist: {missing:?}"
    );
}

#[test]
fn test_host_guide_sources_cover_every_module() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = rust_files(&root);
    assert!(
        files.contains(&root.join("lib.rs")),
        "no sources found under {}",
        root.display()
    );
    let mut uncovered = Vec::new();
    for path in &files {
        let file = path.strip_prefix(&root).unwrap();
        if TEST_ONLY.iter().any(|entry| Path::new(entry) == file)
            || SOURCES.iter().any(|(entry, _)| Path::new(entry) == file)
        {
            continue;
        }
        let source = std::fs::read_to_string(path).unwrap();
        if !public_enums(&source).is_empty() {
            uncovered.push(file);
        }
    }
    assert!(
        uncovered.is_empty(),
        "these sources hold a `pub enum` but aren't in `SOURCES`: {uncovered:?}"
    );
    // Every listed path is a file that exists, so a moved module isn't silently skipped.
    for (path, _) in SOURCES {
        assert!(
            files.contains(&root.join(path)),
            "`SOURCES` names {path}, which isn't under src"
        );
    }
    for path in TEST_ONLY {
        assert!(
            files.contains(&root.join(path)),
            "`TEST_ONLY` names {path}, which isn't under src"
        );
    }
}

#[test]
fn test_host_guide_names_no_unknown_variant() {
    let unknown = unknown_variants(GUIDE, &covered_enums());
    assert!(
        unknown.is_empty(),
        "the host guide names variants the crate doesn't have: {unknown:?}"
    );
}

#[test]
fn test_host_guide_missing_variant_is_reported() {
    let enums = covered_enums();
    assert!(missing_variants(GUIDE, &enums).is_empty());
    let without = GUIDE.replace("`Alert::ClockOff`", "");
    assert_eq!(missing_variants(&without, &enums), ["Alert::ClockOff"]);
    // A stale name is reported too.
    let stale = format!("{GUIDE}\n`Alert::NoSuchAlert`\n");
    assert_eq!(unknown_variants(&stale, &enums), ["Alert::NoSuchAlert"]);
}

#[test]
fn test_host_guide_enum_parser_reads_variants() {
    let sample = r#"
        /// Not this one: `pub enum Hidden { No }` is in a comment.
        pub struct Outcome { pub inner: u8 }

        /// A sample.
        #[derive(Debug, thiserror::Error)]
        #[non_exhaustive]
        pub enum Sample {
            /// A unit variant, with braces in its doc: `{ x }`.
            #[error("unit {0}")]
            Unit,
            /// A tuple variant.
            Tuple(#[from] std::io::Error, Vec<(u8, u8)>),
            /// A struct variant, with nested braces in its payload.
            Struct {
                /// A field.
                #[serde(rename = "a,b")]
                field: Option<Vec<String>>,
                other: [u8; 16],
            },
            /* A block comment, with a comma, */ Last = 7
        }

        pub enum SampleTwo { One }
        pub(crate) enum Inner { Two }
    "#;
    let enums = public_enums(sample);
    assert_eq!(enums.len(), 2);
    assert_eq!(enums[0].0, "Sample");
    assert_eq!(enums[0].1, ["Unit", "Tuple", "Struct", "Last"]);
    assert_eq!(enums[1].0, "SampleTwo");
    assert_eq!(enums[1].1, ["One"]);
}

#[test]
fn test_host_guide_requires_explicit_enum_in_item_macro() {
    let source = r#"
        macro_rules! declare { ($item:item) => { $item }; }
        declare! {
            pub enum HostInventoryOutcome { Paused }
        }
        declare! { pub(crate) enum Internal { Hidden } }
    "#;
    let enums = public_enums(source);
    assert_eq!(enums.len(), 1);
    assert_eq!(enums[0].0, "HostInventoryOutcome");
    assert_eq!(enums[0].1, ["Paused"]);
    assert_eq!(
        missing_variants("", &enums),
        ["HostInventoryOutcome::Paused"]
    );
    assert!(missing_variants("`HostInventoryOutcome::Paused`", &enums).is_empty());
}

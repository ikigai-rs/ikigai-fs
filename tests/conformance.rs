//! The module recipe as one test: `ikigai-conformance` walks the `file`
//! endpoint at `urn:file:{path}` and reports every violation at once.
//!
//! The suite FIRES the actions it checks — including `Sink` — so the kernel
//! under test is a fixture: a fresh temporary directory the jail is rooted at,
//! seeded with one file the `{path}` binding names. Nothing outside that
//! directory is reachable (the jail), and the directory is removed afterwards.
//!
//! Two mounts, two declarations:
//!
//! - [`ikigai_fs::space`] — the default. A file is a live fact, so `Source` is
//!   uncacheable and the suite's cache probe has nothing to hold it to.
//! - [`ikigai_fs::cacheable_space`] — opt-in caching under a golden thread named
//!   after the resource (`depends_on`). Declared `cacheable` so the suite holds
//!   it to that: a read the kernel handed back uncacheable, or one carrying an
//!   empty thread set, is a finding. The endpoint is NOT `pure` — its result
//!   depends on the file — so an empty thread set here would be a real defect
//!   (a read cached forever with nothing to cut it), never a declaration.
//!
//! No opt-outs, no module namespace (there is no RDF face).

use ikigai_conformance::{Fixture, Report, Suite};
use ikigai_core::{EndpointSpace, Kernel, Verb};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// The one endpoint `space()` binds, by description id.
const ENDPOINT: &str = "file";

/// The file the `{path}` template variable names in every fired action. The
/// suite's derived minimal binding would be `x`, which does not exist, so
/// `Source` could not resolve; a seeded file makes every verb a valid call.
const SEEDED: &str = "conformance.txt";

/// The four content verbs `describe()` declares as actions. `Meta` is the
/// kernel's, not the endpoint's.
const VERBS: [Verb; 4] = [Verb::Source, Verb::Exists, Verb::Sink, Verb::Delete];

/// A fresh, empty jail root under the platform temp dir, unique per test.
fn temp_root() -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ikigai-fs-conformance-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(SEEDED), b"seeded for the conformance walk").unwrap();
    dir
}

/// The suite, configured for this module. Every fired action resolves
/// `urn:file:conformance.txt` — the suite forms one target per bound entry, so
/// a binding on any verb's fixture would do, but each verb states its own so
/// the intent survives a suite that looks them up per action.
fn suite() -> Suite {
    VERBS.iter().fold(Suite::new(), |suite, verb| {
        suite.fixture(Fixture::new(ENDPOINT, *verb).binding("path", SEEDED))
    })
}

/// Run `suite` over a kernel rooted at a fresh jail, clean up, and hand back
/// the report.
fn run(suite: Suite, mount: impl FnOnce(&PathBuf) -> EndpointSpace) -> Report {
    let root = temp_root();
    let kernel = Kernel::new(Arc::new(mount(&root)));
    let report = suite.run_blocking(&kernel);
    std::fs::remove_dir_all(&root).ok();
    report
}

/// The walk saw exactly the one endpoint and its four actions. A fifth verb
/// added to `describe()` without a line here changes the count; a declared
/// verb that binds nothing is a stale list.
fn assert_shape(report: &Report) {
    assert_eq!(report.endpoints, 1, "one `file` endpoint: {report}");
    assert_eq!(
        report.actions,
        VERBS.len(),
        "Source/Exists/Sink/Delete actions: {report}"
    );
}

#[test]
fn conforms() {
    let report = run(suite(), |root| ikigai_fs::space(root));
    // Printed even when clean (`--nocapture`): the report is the record.
    eprintln!("{report}");
    assert!(report.is_clean(), "{report}");
    assert_shape(&report);
}

#[test]
fn cacheable_mount_conforms() {
    let report = run(suite().cacheable(ENDPOINT), |root| {
        ikigai_fs::cacheable_space(root)
    });
    // Printed even when clean (`--nocapture`): the report is the record.
    eprintln!("{report}");
    assert!(report.is_clean(), "{report}");
    assert_shape(&report);
}

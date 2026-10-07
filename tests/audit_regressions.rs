//! Regression tests for audit round 3 (ledger #856), ported from both auditors'
//! reproductions (Claude's `audit_probes.rs`, Hermes's `fs-probe`) and deduplicated by
//! root cause. Every test asserts the safe behavior, so each one failed on `01fbfd0`
//! because of the defect it names.
//!
//! - **A** — the ACL and the jail judged a PATH, not the file opened (B1, B2a-c, B7, F3).
//! - **C** — the cacheable mode's golden thread was keyed by the request IRI, so an
//!   alias of a file went stale after a write through another spelling (B4/F1, F2).
//! - **Minors** — B5 (rule specificity), B6/F5 (`as`), B8/F4 (typed `NotFound`, no host
//!   paths in errors), B9 (`Exists` swallowed a failed check).
//! - **B3** is NOT fixed here (ledger #858 is core's): one test pins today's behavior as
//!   the known gap, so the day core seals exclusions it fails and is flipped.

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Error, Iri, Kernel, Request, Result, Verb};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ikigai-fs-regress-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn kernel(root: &Path) -> Kernel {
    Kernel::new(Arc::new(ikigai_fs::space(root)))
}

fn cached_kernel(root: &Path) -> Kernel {
    Kernel::new(Arc::new(ikigai_fs::cacheable_space(root)))
}

fn request(verb: Verb, path: &str) -> Request {
    Request::new(verb, Iri::parse(format!("urn:file:{path}")).unwrap())
}

fn source(k: &Kernel, path: &str, cap: &Capability) -> Result<Vec<u8>> {
    block_on(k.issue(request(Verb::Source, path), cap)).map(|r| r.bytes)
}

fn exists(k: &Kernel, path: &str, cap: &Capability) -> Result<Vec<u8>> {
    block_on(k.issue(request(Verb::Exists, path), cap)).map(|r| r.bytes)
}

fn sink(k: &Kernel, path: &str, body: &[u8], cap: &Capability) -> Result<()> {
    let req = request(Verb::Sink, path).with_arg("content", ArgRef::Inline(body.to_vec()));
    block_on(k.issue(req, cap)).map(|_| ())
}

fn delete(k: &Kernel, path: &str, cap: &Capability) -> Result<()> {
    block_on(k.issue(request(Verb::Delete, path), cap)).map(|_| ())
}

fn read_rule(p: &Path) -> String {
    format!("urn:cap:fs:read:{}", p.display())
}
fn read_deny(p: &Path) -> String {
    format!("urn:cap:fs:read:-{}", p.display())
}

/// A jail holding `secret/k.txt` and `open.txt`, and the README's own capability: read
/// the jail except `secret`.
fn jail_with_secret() -> (PathBuf, Capability) {
    let root = temp_dir("secret");
    std::fs::create_dir_all(root.join("secret")).unwrap();
    std::fs::write(root.join("secret/k.txt"), b"PRIVATE").unwrap();
    std::fs::write(root.join("open.txt"), b"public").unwrap();
    let cap = Capability::scoped([read_rule(&root), read_deny(&root.join("secret"))]);
    (root, cap)
}

fn lossy(r: &Result<Vec<u8>>) -> String {
    match r {
        Ok(b) => format!("Ok({:?})", String::from_utf8_lossy(b)),
        Err(e) => format!("Err({e:?})"),
    }
}

/// Whether the volume holding `dir` folds case (macOS's default APFS does).
fn folds_case(dir: &Path) -> bool {
    let probe = dir.join("case-probe");
    std::fs::write(&probe, b"").unwrap();
    let folds = dir.join("CASE-PROBE").exists();
    std::fs::remove_file(&probe).unwrap();
    folds
}

// --- A: authorize the file you open -------------------------------------------------

/// B1. A dangling link in the jail naming a not-yet-existing file outside it: the old
/// ancestor walk found nothing to canonicalize and `std::fs::write` followed the link.
#[cfg(unix)]
#[test]
fn b1_a_dangling_symlink_leaf_cannot_create_a_file_outside_the_jail() {
    let root = temp_dir("b1-root");
    let outside = temp_dir("b1-outside");
    std::os::unix::fs::symlink(outside.join("planted"), root.join("link")).unwrap();
    let k = kernel(&root);
    let cap = Capability::scoped([format!("urn:cap:fs:write:{}", root.display())]);
    let result = sink(&k, "link", b"written from inside the jail", &cap);
    let root_result = sink(&k, "link", b"even under root", &Capability::root());
    let escaped = outside.join("planted").exists();
    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&outside).ok();
    assert!(
        !escaped,
        "jail escape through a dangling link: {result:?} / {root_result:?}"
    );
    assert!(
        matches!(result, Err(Error::InvalidArgument { .. })),
        "a link is refused, not followed: {result:?}"
    );
}

/// B2a. A case variant of a denied directory on a case-folding volume: the ACL compared
/// the typed spelling, the volume opened the denied file. Skipped where the volume is
/// case-sensitive (Linux CI), since the alias does not exist there.
#[test]
fn b2a_a_case_variant_cannot_bypass_a_deny() {
    let (root, cap) = jail_with_secret();
    if !folds_case(&root) {
        std::fs::remove_dir_all(&root).ok();
        eprintln!("volume is case-sensitive: B2a is not reachable here");
        return;
    }
    let k = kernel(&root);
    let got = source(&k, "SECRET/k.txt", &cap);
    let under_root = source(&k, "SECRET/k.txt", &Capability::root());
    std::fs::remove_dir_all(&root).ok();
    assert!(
        got.is_err(),
        "deny bypassed by a case variant: {}",
        lossy(&got)
    );
    // Not merely denied: the endpoint serves a file under its on-disk spelling only.
    assert!(
        matches!(under_root, Err(Error::InvalidArgument { .. })),
        "a case variant is refused even under root: {}",
        lossy(&under_root)
    );
}

/// B2b. An in-jail symlink into a denied subtree: the jail rightly accepted it (it stays
/// inside), and the ACL judged the link's spelling, not the target's.
#[cfg(unix)]
#[test]
fn b2b_an_in_jail_symlink_cannot_bypass_a_deny() {
    let (root, cap) = jail_with_secret();
    std::os::unix::fs::symlink("secret", root.join("public")).unwrap();
    let k = kernel(&root);
    let direct = source(&k, "secret/k.txt", &cap);
    let via_link = source(&k, "public/k.txt", &cap);
    std::fs::remove_dir_all(&root).ok();
    assert!(direct.is_err(), "sanity: the deny holds on the direct path");
    assert!(
        via_link.is_err(),
        "deny bypassed through an in-jail link: {}",
        lossy(&via_link)
    );
}

/// B2c. The same root cause on an ALLOWLIST and a WRITE: a capability for `<root>/public`
/// only wrote into `private/` through a link inside `public/`.
#[cfg(unix)]
#[test]
fn b2c_an_allowlisted_subtree_cannot_write_outside_itself_through_a_link() {
    let root = temp_dir("b2c");
    std::fs::create_dir_all(root.join("public")).unwrap();
    std::fs::create_dir_all(root.join("private")).unwrap();
    std::os::unix::fs::symlink("../private", root.join("public/up")).unwrap();
    let k = kernel(&root);
    let cap = Capability::scoped([format!(
        "urn:cap:fs:write:{}",
        root.join("public").display()
    )]);
    let direct = sink(&k, "private/direct.txt", b"x", &cap);
    let via_link = sink(&k, "public/up/planted.txt", b"x", &cap);
    let wrote = root.join("private/planted.txt").exists();
    std::fs::remove_dir_all(&root).ok();
    assert!(
        direct.is_err(),
        "sanity: the allowlist refuses private/ directly"
    );
    assert!(!wrote, "allowlist bypassed through a link: {via_link:?}");
}

/// B7, as a race: the old jail checked the deepest existing ancestor, then
/// `create_dir_all` + `write` re-walked the path, so a directory swapped for a link in
/// between was followed out of the jail (5/5 runs escaped on `01fbfd0`, within the first
/// few dozen writes). The deterministic form of this test, with the swap placed exactly
/// between the check and the write, is the unit test
/// `a_swap_after_the_walk_cannot_redirect_the_write` in `src/lib.rs`.
#[cfg(unix)]
#[test]
fn b7_a_racing_swap_cannot_write_outside_the_jail() {
    use std::sync::atomic::AtomicBool;
    let root = temp_dir("b7-root");
    let outside = temp_dir("b7-outside");
    let k = kernel(&root);
    let cap = Capability::root();
    let stop = Arc::new(AtomicBool::new(false));
    let (r2, o2, s2) = (root.clone(), outside.clone(), stop.clone());
    let swapper = std::thread::spawn(move || {
        let d = r2.join("d");
        while !s2.load(Ordering::Relaxed) {
            let _ = std::fs::create_dir(&d);
            let _ = std::fs::remove_dir_all(&d);
            let _ = std::os::unix::fs::symlink(&o2, &d);
            let _ = std::fs::remove_file(&d);
        }
    });
    let mut escaped = false;
    for i in 0..3_000 {
        let _ = sink(&k, &format!("d/f{i}"), b"x", &cap);
        if std::fs::read_dir(&outside)
            .map(|mut it| it.next().is_some())
            .unwrap_or(false)
        {
            escaped = true;
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().unwrap();
    let names: Vec<_> = std::fs::read_dir(&outside)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();
    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&outside).ok();
    assert!(!escaped, "TOCTOU escape: wrote {names:?} outside the jail");
}

/// F3. The jail failed OPEN when the root did not canonicalize: a mount over a missing
/// root skipped containment entirely, and the write materialized the "jail" itself.
#[test]
fn f3_a_root_that_cannot_be_opened_fails_closed() {
    let parent = temp_dir("f3");
    let missing = parent.join("no-such-root");
    let k = kernel(&missing);
    let wrote = sink(
        &k,
        "x.txt",
        b"written under a missing root",
        &Capability::root(),
    );
    let read = source(&k, "x.txt", &Capability::root());
    let there = exists(&k, "x.txt", &Capability::root());
    let created = missing.exists();
    std::fs::remove_dir_all(&parent).ok();
    assert!(
        wrote.is_err(),
        "Sink under a missing root must fail closed: {wrote:?}"
    );
    assert!(!created, "the endpoint created its own jail root");
    assert!(
        read.is_err(),
        "Source under a missing root: {}",
        lossy(&read)
    );
    assert!(
        there.is_err(),
        "Exists under a missing root: {}",
        lossy(&there)
    );
}

// --- C: one file, one thread ----------------------------------------------------------

/// A spelling the endpoint either serves fresh or refuses outright, but never serves
/// stale.
fn fresh_or_refused(got: Result<Vec<u8>>, want: &[u8], what: &str) {
    match got {
        Ok(bytes) => assert_eq!(
            String::from_utf8_lossy(&bytes),
            String::from_utf8_lossy(want),
            "{what}: a stale answer"
        ),
        Err(Error::InvalidArgument { .. }) => {}
        Err(e) => panic!("{what}: unexpected {e:?}"),
    }
}

/// B4 / F1. `./notes.txt` and `notes.txt` named one file under two IRIs, so two golden
/// threads: a `Sink` through either cut only its own, and a cached read through the
/// other went on serving the old bytes. Both directions.
#[test]
fn b4_f1_no_alias_of_a_file_serves_a_stale_read_after_a_write() {
    let root = temp_dir("b4");
    std::fs::write(root.join("notes.txt"), b"v1").unwrap();
    let k = cached_kernel(&root);
    let cap = Capability::root();

    // Prime both spellings, then write through the canonical one.
    assert_eq!(source(&k, "notes.txt", &cap).unwrap(), b"v1");
    let _ = source(&k, "./notes.txt", &cap);
    sink(&k, "notes.txt", b"v2", &cap).unwrap();
    fresh_or_refused(
        source(&k, "./notes.txt", &cap),
        b"v2",
        "read ./notes.txt after Sink notes.txt",
    );

    // The reverse: a write through the alias must not leave the canonical read stale.
    assert_eq!(source(&k, "notes.txt", &cap).unwrap(), b"v2");
    let _ = sink(&k, "./notes.txt", b"v3", &cap);
    let on_disk = std::fs::read(root.join("notes.txt")).unwrap();
    let got = source(&k, "notes.txt", &cap).unwrap();
    std::fs::remove_dir_all(&root).ok();
    assert_eq!(
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&on_disk),
        "a cached read of notes.txt disagrees with the file after Sink ./notes.txt"
    );
}

/// F2. The same defect on `Exists`: `false` cached under `./missing.txt` stayed `false`
/// after the file was created through `missing.txt`.
#[test]
fn f2_no_alias_serves_a_stale_existence_answer() {
    let root = temp_dir("f2");
    let k = cached_kernel(&root);
    let cap = Capability::root();
    let _ = exists(&k, "./missing.txt", &cap);
    sink(&k, "missing.txt", b"now here", &cap).unwrap();
    let got = exists(&k, "./missing.txt", &cap);
    std::fs::remove_dir_all(&root).ok();
    fresh_or_refused(got, b"true", "Exists ./missing.txt after Sink missing.txt");
}

/// The case-folding twin of B4: on a volume that folds case, `NOTES.txt` and `notes.txt`
/// are one file, so a cached read through one must not outlive a write through the other.
#[test]
fn a_case_alias_serves_no_stale_read_after_a_write() {
    let root = temp_dir("case-alias");
    if !folds_case(&root) {
        std::fs::remove_dir_all(&root).ok();
        eprintln!("volume is case-sensitive: the case alias does not exist here");
        return;
    }
    std::fs::write(root.join("notes.txt"), b"v1").unwrap();
    let k = cached_kernel(&root);
    let cap = Capability::root();
    let _ = source(&k, "NOTES.txt", &cap);
    sink(&k, "notes.txt", b"v2", &cap).unwrap();
    let got = source(&k, "NOTES.txt", &cap);
    let wrote = sink(&k, "Notes.txt", b"v3", &cap);
    let on_disk = std::fs::read(root.join("notes.txt")).unwrap();
    std::fs::remove_dir_all(&root).ok();
    fresh_or_refused(got, b"v2", "read NOTES.txt after Sink notes.txt");
    assert!(wrote.is_err(), "a write through a case alias is refused");
    assert_eq!(on_disk, b"v2", "and leaves the file untouched");
}

// --- minors ---------------------------------------------------------------------------

/// B5. Specificity was the rule STRING's length, so an allow spelling the same directory
/// with a trailing slash outranked the deny and the tie-break never ran.
#[test]
fn b5_deny_wins_a_tie_on_one_directory_spelled_two_ways() {
    let root = temp_dir("b5");
    std::fs::create_dir_all(root.join("secret")).unwrap();
    std::fs::write(root.join("secret/k.txt"), b"PRIVATE").unwrap();
    let k = kernel(&root);
    let cap = Capability::scoped([
        format!("urn:cap:fs:read:{}/", root.join("secret").display()),
        format!("urn:cap:fs:read:{}/./", root.join("secret").display()),
        read_deny(&root.join("secret")),
    ]);
    let got = source(&k, "secret/k.txt", &cap);
    std::fs::remove_dir_all(&root).ok();
    assert!(
        matches!(got, Err(Error::Denied(_))),
        "`<root>/secret/` and `-<root>/secret` name one directory; deny wins: {}",
        lossy(&got)
    );
}

/// B6. `as` is declared `one_of [application/octet-stream]`, but any value was honored by
/// relabeling the bytes unconverted: a `.txt` upload came back as `text/html`.
#[test]
fn b6_an_undeclared_as_is_refused_not_relabeled() {
    let root = temp_dir("b6");
    std::fs::write(root.join("upload.txt"), b"<script>alert(1)</script>").unwrap();
    let k = kernel(&root);
    let req =
        request(Verb::Source, "upload.txt").with_arg("as", ArgRef::Inline(b"text/html".to_vec()));
    let got = block_on(k.issue(req, &Capability::root()));
    let raw = request(Verb::Source, "upload.txt")
        .with_arg("as", ArgRef::Inline(b"application/octet-stream".to_vec()));
    let declared = block_on(k.issue(raw, &Capability::root()));
    std::fs::remove_dir_all(&root).ok();
    match got {
        Err(Error::InvalidArgument { name, .. }) => assert_eq!(name, "as"),
        other => panic!("an undeclared `as` must be refused: {other:?}"),
    }
    assert_eq!(
        declared.unwrap().repr_type.media_type,
        "application/octet-stream"
    );
}

/// F5. A CRLF in `as` reached the representation's media type verbatim, and an HTTP
/// edge writes that into a `Content-Type` header.
#[test]
fn f5_control_characters_never_reach_a_media_type() {
    let root = temp_dir("f5");
    std::fs::write(root.join("data.bin"), b"\x00\x01binary").unwrap();
    let k = kernel(&root);
    let req = request(Verb::Source, "data.bin").with_arg(
        "as",
        ArgRef::Inline(b"application/octet-stream\r\nX-Evil: 1".to_vec()),
    );
    let got = block_on(k.issue(req, &Capability::root()));
    std::fs::remove_dir_all(&root).ok();
    match got {
        Ok(rep) => panic!("refused, not echoed: {:?}", rep.repr_type.canonical()),
        Err(e) => assert!(matches!(e, Error::InvalidArgument { .. }), "{e:?}"),
    }
}

/// B8. A missing file was a generic `Endpoint` failure, not core's typed `NotFound`, so
/// a composite falling back over its absence could not hang on its thread and an edge
/// could not answer 404.
#[test]
fn b8_an_absent_file_is_typed_not_found() {
    let root = temp_dir("b8");
    let k = kernel(&root);
    let cap = Capability::root();
    let read = source(&k, "absent.txt", &cap);
    let deeper = source(&k, "no/such/dir/absent.txt", &cap);
    let gone = delete(&k, "absent.txt", &cap);
    std::fs::remove_dir_all(&root).ok();
    assert!(
        matches!(read, Err(Error::NotFound(_))),
        "Source: {}",
        lossy(&read)
    );
    assert!(
        matches!(deeper, Err(Error::NotFound(_))),
        "Source deeper: {}",
        lossy(&deeper)
    );
    assert!(matches!(gone, Err(Error::NotFound(_))), "Delete: {gone:?}");
}

/// B8 / F4. Errors carried the absolute host path, leaking where the jail lives on a
/// module whose premise is hiding the root behind `urn:file:`.
#[test]
fn f4_errors_never_name_the_host_path() {
    let root = temp_dir("f4");
    std::fs::create_dir_all(root.join("dir")).unwrap();
    std::fs::write(root.join("plain.txt"), b"x").unwrap();
    let canonical = root.canonicalize().unwrap();
    let k = kernel(&root);
    let cap = Capability::root();
    let errors: Vec<Error> = [
        source(&k, "nope.txt", &cap).map(|_| ()),
        delete(&k, "dir", &cap),
        source(&k, "dir", &cap).map(|_| ()),
        sink(&k, "plain.txt/under-a-file", b"x", &cap),
    ]
    .into_iter()
    .map(|r| r.expect_err("each of these fails"))
    .collect();
    std::fs::remove_dir_all(&root).ok();
    for e in errors {
        let text = format!("{e} {e:?}");
        for host in [root.display().to_string(), canonical.display().to_string()] {
            assert!(!text.contains(&host), "error names the host path: {text}");
        }
    }
}

/// B9. `Exists` answered `false` for a file that exists when the check itself failed:
/// `Path::exists` swallows every error, EACCES included.
#[cfg(unix)]
#[test]
fn b9_exists_surfaces_a_failed_check() {
    use std::os::unix::fs::PermissionsExt;
    let root = temp_dir("b9");
    let locked = root.join("locked");
    std::fs::create_dir_all(&locked).unwrap();
    std::fs::write(locked.join("present.txt"), b"here").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root ignores mode bits, so the failure cannot be provoked there.
    let provokable = std::fs::read_dir(&locked).is_err();
    let k = kernel(&root);
    let got = exists(&k, "locked/present.txt", &Capability::root());
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_dir_all(&root).ok();
    if !provokable {
        eprintln!("running as a user that ignores mode bits: B9 is not reachable here");
        return;
    }
    assert!(
        got.is_err(),
        "Exists must surface the failed check, not answer: {}",
        lossy(&got)
    );
}

// --- ledger #230: a scope matches the jail under either spelling of its root ----------

/// A capability minted against the root's CANONICAL spelling (`/private/var/…` on macOS,
/// where the temp dir is `/var/…`) grants and denies exactly as the mount spelling does.
#[test]
fn a_scope_matches_the_jail_under_its_canonical_spelling() {
    let (root, _) = jail_with_secret();
    let canonical = root.canonicalize().unwrap();
    let k = kernel(&root);
    let cap = Capability::scoped([read_rule(&canonical), read_deny(&canonical.join("secret"))]);
    let open = source(&k, "open.txt", &cap);
    let secret = source(&k, "secret/k.txt", &cap);
    std::fs::remove_dir_all(&root).ok();
    assert_eq!(open.unwrap(), b"public");
    assert!(
        matches!(secret, Err(Error::Denied(_))),
        "{}",
        lossy(&secret)
    );
}

// --- B3: a deny survives delegation (ledger #858, fixed in core 0.1.86) --------------

/// A deny rule is a deny-shaped scope, and since ikigai-core 0.1.86 `attenuate` and
/// `clamp` keep every deny either side holds (`is_deny_scope`). This was pinned as a
/// KNOWN GAP until then: a delegate attenuated to `{read:/root}` from
/// `{read:/root, read:-/root/secret}`, or a peer clamped the same way, read the secret.
#[test]
fn b3_a_deny_survives_attenuation_and_clamp() {
    let (root, parent) = jail_with_secret();
    let k = kernel(&root);
    let parent_read = source(&k, "secret/k.txt", &parent);
    let child = parent.attenuate([read_rule(&root)]);
    let attenuated = source(&k, "secret/k.txt", &child);
    let clamped = source(
        &k,
        "secret/k.txt",
        &parent.clamp(&Capability::scoped([read_rule(&root)])),
    );
    std::fs::remove_dir_all(&root).ok();
    assert!(parent_read.is_err(), "sanity: the parent denies");
    assert!(attenuated.is_err(), "an attenuated delegate must not read past the deny");
    assert!(clamped.is_err(), "a clamped peer must not read past the deny");
}

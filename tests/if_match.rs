//! **A conditional `Sink`** (ledger #3054): `if-match` carries the content id of the `Source`
//! representation a writer read, and the write replaces the file only if that is still its
//! content id, refusing a stale token with [`Error::Conflict`] naming the current one. It is
//! the writable binding `ikigai-name`'s `urn:name:registry-source` asks for (its ledger #3046).
//! Every race here runs against the real endpoint, on real files, through independent kernels.
#![cfg(unix)]

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use futures::executor::block_on;
use ikigai_core::{
    ArgRef, Body, BodyIssue, Bytes, Capability, ContentId, Error, Iri, Kernel, Representation,
    Request, Result, Verb,
};
use ikigai_fs::{space, LOCK_WAIT};

struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "ikigai-fs-if-match-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        Root(dir)
    }

    fn seed(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.0.join(name), bytes).unwrap();
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.0.join(name)).unwrap()
    }

    /// Every name in the root, sorted: a staging file shows here.
    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// A kernel of its own over `root`: what a second host mounting the same file is.
fn kernel(root: &Path) -> Kernel {
    Kernel::new(Arc::new(space(root)))
}

fn iri(name: &str) -> Iri {
    Iri::parse(format!("urn:file:{name}")).unwrap()
}

fn issue(kernel: &Kernel, request: Request) -> Result<Representation> {
    block_on(kernel.issue(request, &Capability::root()))
}

/// What `ikigai-name` keeps from its read: the Source representation's content id.
fn token(kernel: &Kernel, name: &str) -> ContentId {
    issue(kernel, Request::new(Verb::Source, iri(name)))
        .unwrap()
        .content_id()
}

fn sink_if_match(kernel: &Kernel, name: &str, content: &[u8], expected: &str) -> Result<()> {
    issue(
        kernel,
        Request::new(Verb::Sink, iri(name))
            .with_arg("content", ArgRef::Inline(content.to_vec()))
            .with_arg("if-match", ArgRef::Inline(expected.as_bytes().to_vec())),
    )
    .map(|_| ())
}

fn conflict_detail(result: Result<()>) -> String {
    match result {
        Err(Error::Conflict(detail)) => detail,
        other => panic!("expected Conflict, got {other:?}"),
    }
}

#[test]
fn a_current_token_replaces_the_file() {
    let root = Root::new("current");
    root.seed("registry.json", br#"{"namespaces":[]}"#);
    let kernel = kernel(&root.0);

    let read = token(&kernel, "registry.json");
    sink_if_match(&kernel, "registry.json", b"{}", &read.to_string()).unwrap();

    assert_eq!(root.read("registry.json"), b"{}");
    assert_eq!(root.names(), ["registry.json"]);
}

#[test]
fn a_stale_token_is_refused_naming_the_current_one_and_changes_nothing() {
    let root = Root::new("stale");
    root.seed("registry.json", b"[1]");
    let kernel = kernel(&root.0);

    let stale = token(&kernel, "registry.json");
    sink_if_match(&kernel, "registry.json", b"[2]", &stale.to_string()).unwrap();
    let current = token(&kernel, "registry.json");

    let detail = conflict_detail(sink_if_match(
        &kernel,
        "registry.json",
        b"[3]",
        &stale.to_string(),
    ));

    assert_ne!(stale, current);
    assert!(detail.contains(&current.to_string()), "{detail}");
    assert!(detail.contains("urn:file:registry.json"), "{detail}");
    assert!(detail.contains("read it again"), "{detail}");
    assert!(!detail.contains(&*root.0.to_string_lossy()), "{detail}");
    assert_eq!(root.read("registry.json"), b"[2]");
    assert_eq!(root.names(), ["registry.json"]);
}

/// The token identifies a `Source` representation, type and bytes, so it is the same whatever
/// spelling of the rule fixed the type: an extension, the UTF-8 fallback, or raw bytes.
#[test]
fn the_token_of_every_source_face_is_honored() {
    let root = Root::new("faces");
    let kernel = kernel(&root.0);
    for (name, bytes) in [
        ("a.json", &b"{}"[..]),
        ("noextension", &b"plain text"[..]),
        ("binary", &[0xff, 0xfe, 0x00][..]),
        ("empty.json", &b""[..]),
    ] {
        root.seed(name, bytes);
        let default_face = token(&kernel, name);
        sink_if_match(&kernel, name, b"", &default_face.to_string()).unwrap();

        root.seed(name, bytes);
        let raw_face = issue(
            &kernel,
            Request::new(Verb::Source, iri(name))
                .with_arg("as", ArgRef::Inline(b"application/octet-stream".to_vec())),
        )
        .unwrap()
        .content_id();
        sink_if_match(&kernel, name, b"", &raw_face.to_string()).unwrap();
        assert_eq!(root.read(name), b"", "{name}");
    }
}

/// The digest of the bytes alone is no token: it does not identify the representation.
#[test]
fn the_bare_digest_of_the_bytes_is_not_a_token() {
    let root = Root::new("bare");
    root.seed("a.json", b"{}");
    let kernel = kernel(&root.0);

    let bare = ContentId::of(b"{}");
    let detail = conflict_detail(sink_if_match(&kernel, "a.json", b"[]", &bare.to_string()));

    assert!(detail.contains(&token(&kernel, "a.json").to_string()));
    assert_eq!(root.read("a.json"), b"{}");
}

#[test]
fn a_missing_file_matches_no_token_and_nothing_is_created() {
    let root = Root::new("missing");
    let kernel = kernel(&root.0);
    let any = ContentId::of(b"anything").to_string();

    let detail = conflict_detail(sink_if_match(&kernel, "absent.json", b"{}", &any));
    assert!(detail.contains("urn:file:absent.json"), "{detail}");
    assert!(detail.contains("does not exist"), "{detail}");

    conflict_detail(sink_if_match(&kernel, "new/dir/absent.json", b"{}", &any));
    assert!(root.names().is_empty(), "{:?}", root.names());
}

#[test]
fn a_token_that_is_not_a_content_id_is_refused_and_changes_nothing() {
    let root = Root::new("malformed");
    root.seed("a.txt", b"old");
    let kernel = kernel(&root.0);

    for bad in ["", "*", "b3:", "b3:zz", "sha256:00"] {
        match sink_if_match(&kernel, "a.txt", b"new", bad) {
            Err(Error::InvalidArgument { name, .. }) => assert_eq!(name, "if-match"),
            other => panic!("{bad:?}: expected InvalidArgument, got {other:?}"),
        }
    }
    assert_eq!(root.read("a.txt"), b"old");
}

/// A body attached to the `Sink` streams into the staging file first; the comparison is still
/// made when it is published, and a stale token leaves the target and no staging file.
#[test]
fn a_streamed_body_with_a_stale_token_leaves_nothing_behind() {
    let root = Root::new("streamed");
    root.seed("a.txt", b"old");
    let kernel = kernel(&root.0);
    let current = token(&kernel, "a.txt");
    let stale = ContentId::of(b"stale").to_string();

    let attached = |expected: String| {
        let chunks: Vec<Result<Bytes>> =
            vec![Ok(Bytes::from_static(b"ne")), Ok(Bytes::from_static(b"w"))];
        let body = Body::once(futures::stream::iter(chunks));
        block_on(
            kernel.issue_with(
                Request::new(Verb::Sink, iri("a.txt"))
                    .with_arg("if-match", ArgRef::Inline(expected.into_bytes())),
                &Capability::root(),
                BodyIssue::new().attach("content", body),
            ),
        )
    };

    let refused = attached(stale);
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    assert_eq!(root.read("a.txt"), b"old");
    assert_eq!(root.names(), ["a.txt"]);

    attached(current.to_string()).unwrap();
    assert_eq!(root.read("a.txt"), b"new");
    assert_eq!(root.names(), ["a.txt"]);
}

/// The race `ikigai-name`'s own regression runs against its test store, here against the real
/// endpoint: writers from one token, each in a kernel of its own, released together. Exactly
/// one replaces the file; every other is told so, with the winner's token.
#[test]
fn racing_writers_from_one_token_commit_exactly_one_replacement() {
    const WRITERS: usize = 8;
    const ROUNDS: usize = 200;
    let root = Root::new("race");
    root.seed("registry.json", b"round 0");
    let reader = kernel(&root.0);

    for round in 0..ROUNDS {
        let read = token(&reader, "registry.json").to_string();
        let barrier = Barrier::new(WRITERS);
        let outcomes: Vec<(Vec<u8>, Result<()>)> = std::thread::scope(|scope| {
            let writers: Vec<_> = (0..WRITERS)
                .map(|writer| {
                    let (root, read, barrier) = (&root.0, &read, &barrier);
                    scope.spawn(move || {
                        let kernel = kernel(root);
                        let content = format!("round {round} writer {writer}").into_bytes();
                        barrier.wait();
                        let result = sink_if_match(&kernel, "registry.json", &content, read);
                        (content, result)
                    })
                })
                .collect();
            writers.into_iter().map(|w| w.join().unwrap()).collect()
        });

        let current = token(&reader, "registry.json").to_string();
        let on_disk = root.read("registry.json");
        let winners: Vec<&Vec<u8>> = outcomes
            .iter()
            .filter(|(_, result)| result.is_ok())
            .map(|(content, _)| content)
            .collect();
        assert_eq!(winners.len(), 1, "round {round}: {outcomes:?}");
        assert_eq!(
            winners[0], &on_disk,
            "round {round}: the winner's edit persists"
        );
        for (_, result) in &outcomes {
            match result {
                Ok(()) => {}
                Err(Error::Conflict(detail)) => {
                    assert!(detail.contains(&current), "round {round}: {detail}")
                }
                Err(other) => panic!("round {round}: a loser must get Conflict: {other:?}"),
            }
        }
        assert_eq!(root.names(), ["registry.json"], "round {round}");
    }
}

/// A read that may overlap a replacement: a `Source` refuses torn bytes and tells its caller to
/// read again, which is no part of the write's contract.
fn read_settled(kernel: &Kernel, name: &str) -> Representation {
    loop {
        match issue(kernel, Request::new(Verb::Source, iri(name))) {
            Ok(read) => return read,
            Err(Error::Conflict(detail)) if detail.contains("changed while read") => {}
            Err(Error::Endpoint(detail)) if detail.contains("retry") => {}
            Err(other) => panic!("{other:?}"),
        }
    }
}

/// One read-modify-write of a counter file: read it, add one, write back on the token read,
/// and read again on a Conflict. A lost update would leave the count short.
fn increment(kernel: &Kernel, name: &str) {
    loop {
        let read = read_settled(kernel, name);
        let count: u64 = std::str::from_utf8(&read.bytes).unwrap().parse().unwrap();
        let next = (count + 1).to_string();
        match sink_if_match(
            kernel,
            name,
            next.as_bytes(),
            &read.content_id().to_string(),
        ) {
            Ok(()) => return,
            Err(Error::Conflict(_)) => continue,
            Err(other) => panic!("{other:?}"),
        }
    }
}

const COUNTER_ROOT: &str = "IKIGAI_FS_IF_MATCH_COUNTER_ROOT";
const INCREMENTS: u64 = 100;

/// Not a test of its own: what each process of the test below runs (it does nothing unless
/// that test set the variable).
#[test]
fn counter_child_process() {
    if let Some(root) = std::env::var_os(COUNTER_ROOT) {
        let kernel = kernel(Path::new(&root));
        for _ in 0..INCREMENTS {
            increment(&kernel, "count.txt");
        }
    }
}

/// The comparison and the replacement are one operation across processes, not only across a
/// process's threads: separate processes counting on one file lose no update.
#[test]
fn separate_processes_counting_on_one_file_lose_no_update() {
    const PROCESSES: u64 = 4;
    let root = Root::new("processes");
    root.seed("count.txt", b"0");

    let exe = std::env::current_exe().unwrap();
    let children: Vec<_> = (0..PROCESSES)
        .map(|_| {
            std::process::Command::new(&exe)
                .args(["--exact", "counter_child_process"])
                .env(COUNTER_ROOT, &root.0)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    assert_eq!(
        root.read("count.txt"),
        (PROCESSES * INCREMENTS).to_string().into_bytes()
    );
    assert_eq!(root.names(), ["count.txt"]);
}

/// An exclusive lock on `dir`, as a conditional write holds it across its comparison and its
/// replacement.
fn hold_lock(dir: &Path) -> std::fs::File {
    let handle = std::fs::File::open(dir).unwrap();
    rustix::fs::flock(handle.as_fd(), rustix::fs::FlockOperation::LockExclusive).unwrap();
    handle
}

/// An unconditional `Sink` or a `Delete` landing between another writer's comparison and its
/// replacement would be erased unseen, so they wait out the same lock.
#[test]
fn an_unconditional_write_and_a_delete_wait_for_a_conditional_write_in_progress() {
    let root = Root::new("waits");
    root.seed("a.txt", b"old");
    root.seed("b.txt", b"old");

    for request in [
        Request::new(Verb::Sink, iri("a.txt")).with_arg("content", ArgRef::Inline(b"new".to_vec())),
        Request::new(Verb::Delete, iri("b.txt")),
    ] {
        let held = hold_lock(&root.0);
        let (done, finished) = mpsc::channel();
        let kernel = kernel(&root.0);
        let writer = std::thread::spawn(move || {
            let result = issue(&kernel, request).map(|_| ());
            done.send(()).unwrap();
            result
        });

        assert!(
            finished.recv_timeout(Duration::from_millis(300)).is_err(),
            "the write finished while the lock was held"
        );
        drop(held);
        writer.join().unwrap().unwrap();
    }
    assert_eq!(root.read("a.txt"), b"new");
    assert_eq!(root.names(), ["a.txt"]);
}

/// Whoever holds the lock (anyone who can open the directory can) can only make a write wait so
/// long: past [`LOCK_WAIT`] it is refused as transient and changes nothing.
#[test]
fn a_lock_held_past_the_wait_is_a_transient_refusal() {
    let root = Root::new("held");
    root.seed("a.txt", b"old");
    let kernel = kernel(&root.0);
    let read = token(&kernel, "a.txt").to_string();

    let _held = hold_lock(&root.0);
    let started = std::time::Instant::now();
    let result = sink_if_match(&kernel, "a.txt", b"new", &read);

    assert!(started.elapsed() >= LOCK_WAIT);
    match result {
        Err(Error::Unavailable(detail)) => {
            assert!(detail.contains("urn:file:a.txt"), "{detail}");
            assert!(detail.contains("retry"), "{detail}");
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
    assert_eq!(root.read("a.txt"), b"old");
    assert_eq!(root.names(), ["a.txt"]);
}

#[test]
fn if_match_on_a_delete_is_refused_rather_than_ignored() {
    let root = Root::new("delete");
    root.seed("a.txt", b"old");
    let kernel = kernel(&root.0);
    let read = token(&kernel, "a.txt").to_string();

    let result = issue(
        &kernel,
        Request::new(Verb::Delete, iri("a.txt"))
            .with_arg("if-match", ArgRef::Inline(read.into_bytes())),
    );

    assert!(
        matches!(&result, Err(Error::InvalidArgument { name, .. }) if name == "if-match"),
        "{result:?}"
    );
    assert_eq!(root.read("a.txt"), b"old");
}

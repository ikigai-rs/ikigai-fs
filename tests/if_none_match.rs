//! **A create-only `Sink`** (ledger #3297): `if-none-match=*` writes the file only if it does not
//! exist yet, refusing with [`Error::Conflict`] when it does. And a create that loses the race to
//! another writer is a `Conflict` too, conditional or not, so a caller can tell a race from a
//! failure by its kind. Every race here runs against the real endpoint, on real files, through
//! independent kernels.
#![cfg(unix)]

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use futures::executor::block_on;
use ikigai_core::{
    ArgRef, Body, BodyIssue, Bytes, Capability, ContentId, Error, Iri, Kernel, Representation,
    Request, Result, Verb,
};
use ikigai_fs::space;

struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "ikigai-fs-if-none-match-{}-{name}-{}",
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

fn sink(kernel: &Kernel, name: &str, content: &[u8]) -> Result<()> {
    issue(
        kernel,
        Request::new(Verb::Sink, iri(name)).with_arg("content", ArgRef::Inline(content.to_vec())),
    )
    .map(|_| ())
}

fn sink_create_only(kernel: &Kernel, name: &str, content: &[u8]) -> Result<()> {
    sink_if_none_match(kernel, name, content, "*")
}

fn sink_if_none_match(kernel: &Kernel, name: &str, content: &[u8], value: &str) -> Result<()> {
    issue(
        kernel,
        Request::new(Verb::Sink, iri(name))
            .with_arg("content", ArgRef::Inline(content.to_vec()))
            .with_arg("if-none-match", ArgRef::Inline(value.as_bytes().to_vec())),
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
fn an_absent_file_is_created_with_its_missing_directories() {
    let root = Root::new("absent");
    let kernel = kernel(&root.0);

    sink_create_only(&kernel, "a.json", b"{}").unwrap();
    sink_create_only(&kernel, "new/dir/b.json", b"[]").unwrap();

    assert_eq!(root.read("a.json"), b"{}");
    assert_eq!(root.read("new/dir/b.json"), b"[]");
    assert_eq!(root.names(), ["a.json", "new"]);
}

#[test]
fn an_existing_file_is_refused_naming_the_request_and_changes_nothing() {
    let root = Root::new("existing");
    root.seed("a.json", b"theirs");
    let kernel = kernel(&root.0);

    let detail = conflict_detail(sink_create_only(&kernel, "a.json", b"mine"));

    assert!(detail.contains("urn:file:a.json"), "{detail}");
    assert!(detail.contains("already exists"), "{detail}");
    assert!(detail.contains("read it again"), "{detail}");
    assert!(!detail.contains(&*root.0.to_string_lossy()), "{detail}");
    assert_eq!(root.read("a.json"), b"theirs");
    assert_eq!(root.names(), ["a.json"]);
}

/// An empty file exists: the condition is about the name, never the content.
#[test]
fn an_existing_empty_file_is_refused() {
    let root = Root::new("empty");
    root.seed("a.json", b"");
    let kernel = kernel(&root.0);

    conflict_detail(sink_create_only(&kernel, "a.json", b"mine"));

    assert_eq!(root.read("a.json"), b"");
}

/// A directory at the name is the refusal any `Sink` gets for one, which says what is wrong.
#[test]
fn a_directory_at_the_name_is_refused_as_a_directory() {
    let root = Root::new("directory");
    std::fs::create_dir(root.0.join("d")).unwrap();
    let kernel = kernel(&root.0);

    let refused = sink_create_only(&kernel, "d", b"mine");

    assert!(
        matches!(&refused, Err(Error::InvalidArgument { name, .. }) if name == "path"),
        "{refused:?}"
    );
    assert!(root.0.join("d").is_dir());
}

/// `*` is the one value: an entity tag here would be a condition this endpoint does not make.
#[test]
fn a_value_other_than_star_is_refused_and_changes_nothing() {
    let root = Root::new("malformed");
    let kernel = kernel(&root.0);
    let content_id = ContentId::of(b"anything").to_string();

    for bad in ["", "**", " *", "\"*\"", "true", content_id.as_str()] {
        match sink_if_none_match(&kernel, "a.txt", b"new", bad) {
            Err(Error::InvalidArgument { name, .. }) => assert_eq!(name, "if-none-match"),
            other => panic!("{bad:?}: expected InvalidArgument, got {other:?}"),
        }
    }
    assert!(root.names().is_empty(), "{:?}", root.names());
}

/// One asks that the file exist and the other that it not: no file satisfies both.
#[test]
fn if_match_with_if_none_match_is_refused_and_changes_nothing() {
    let root = Root::new("both");
    root.seed("a.txt", b"old");
    let kernel = kernel(&root.0);
    let read = issue(&kernel, Request::new(Verb::Source, iri("a.txt")))
        .unwrap()
        .content_id()
        .to_string();

    let result = issue(
        &kernel,
        Request::new(Verb::Sink, iri("a.txt"))
            .with_arg("content", ArgRef::Inline(b"new".to_vec()))
            .with_arg("if-match", ArgRef::Inline(read.into_bytes()))
            .with_arg("if-none-match", ArgRef::Inline(b"*".to_vec())),
    );

    assert!(
        matches!(&result, Err(Error::InvalidArgument { name, .. }) if name == "if-none-match"),
        "{result:?}"
    );
    assert_eq!(root.read("a.txt"), b"old");
}

#[test]
fn if_none_match_on_a_delete_is_refused_rather_than_ignored() {
    let root = Root::new("delete");
    root.seed("a.txt", b"old");
    let kernel = kernel(&root.0);

    let result = issue(
        &kernel,
        Request::new(Verb::Delete, iri("a.txt"))
            .with_arg("if-none-match", ArgRef::Inline(b"*".to_vec())),
    );

    assert!(
        matches!(&result, Err(Error::InvalidArgument { name, .. }) if name == "if-none-match"),
        "{result:?}"
    );
    assert_eq!(root.read("a.txt"), b"old");
}

/// A body attached to the `Sink` is refused as inline content is, and leaves no staging file.
#[test]
fn a_streamed_body_creates_once_and_is_then_refused() {
    let root = Root::new("streamed");
    let kernel = kernel(&root.0);

    let attached = || {
        let chunks: Vec<Result<Bytes>> =
            vec![Ok(Bytes::from_static(b"ne")), Ok(Bytes::from_static(b"w"))];
        let body = Body::once(futures::stream::iter(chunks));
        block_on(
            kernel.issue_with(
                Request::new(Verb::Sink, iri("a.txt"))
                    .with_arg("if-none-match", ArgRef::Inline(b"*".to_vec())),
                &Capability::root(),
                BodyIssue::new().attach("content", body),
            ),
        )
    };

    attached().unwrap();
    assert_eq!(root.read("a.txt"), b"new");
    root.seed("a.txt", b"theirs");

    let refused = attached();
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    assert_eq!(root.read("a.txt"), b"theirs");
    assert_eq!(root.names(), ["a.txt"]);
}

/// An exclusive lock on `dir`, as a write holds it around publication.
fn hold_lock(dir: &Path) -> std::fs::File {
    let handle = std::fs::File::open(dir).unwrap();
    rustix::fs::flock(handle.as_fd(), rustix::fs::FlockOperation::LockExclusive).unwrap();
    handle
}

/// Two writers each find `a.txt` missing and stage their content before either publishes: the
/// directory's lock holds them there, and is released once both staging files are visible. The
/// create is then a true race, every run, and the outcomes come back with what each one wrote.
fn two_writers_create_one_file<W>(
    root: &Path,
    names: impl Fn() -> Vec<String>,
    write: W,
) -> Outcomes
where
    W: Fn(&Kernel, &[u8]) -> Result<()> + Sync,
{
    let held = hold_lock(root);
    std::thread::scope(|scope| {
        let writers: Vec<_> = [&b"first"[..], &b"second"[..]]
            .into_iter()
            .map(|content| {
                let write = &write;
                scope.spawn(move || (content.to_vec(), write(&kernel(root), content)))
            })
            .collect();

        let started = Instant::now();
        while names().len() < 2 {
            assert!(
                started.elapsed() < Duration::from_secs(4),
                "both writers should have staged: {:?}",
                names()
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(held);
        writers.into_iter().map(|w| w.join().unwrap()).collect()
    })
}

type Outcomes = Vec<(Vec<u8>, Result<()>)>;

/// Exactly one of the two created the file, its bytes persist, and the other was told so.
fn assert_one_created(root: &Root, outcomes: &Outcomes) {
    let winners: Vec<&Vec<u8>> = outcomes
        .iter()
        .filter(|(_, result)| result.is_ok())
        .map(|(content, _)| content)
        .collect();
    assert_eq!(winners.len(), 1, "{outcomes:?}");
    assert_eq!(*winners[0], root.read("a.txt"));
    for (_, result) in outcomes {
        match result {
            Ok(()) => {}
            Err(Error::Conflict(detail)) => {
                assert!(detail.contains("urn:file:a.txt"), "{detail}");
                assert!(detail.contains("another writer"), "{detail}");
                assert!(detail.contains("read it again"), "{detail}");
                assert!(!detail.contains(&*root.0.to_string_lossy()), "{detail}");
            }
            Err(other) => panic!("a loser must get Conflict: {other:?}"),
        }
    }
    assert_eq!(root.names(), ["a.txt"]);
}

#[test]
fn two_unconditional_writers_creating_one_file_lose_the_race_as_conflict() {
    let root = Root::new("race-unconditional");
    let outcomes = two_writers_create_one_file(
        &root.0,
        || root.names(),
        |kernel, content| sink(kernel, "a.txt", content),
    );
    assert_one_created(&root, &outcomes);
}

#[test]
fn two_create_only_writers_creating_one_file_lose_the_race_as_conflict() {
    let root = Root::new("race-create-only");
    let outcomes = two_writers_create_one_file(
        &root.0,
        || root.names(),
        |kernel, content| sink_create_only(kernel, "a.txt", content),
    );
    assert_one_created(&root, &outcomes);
}

/// Released together, each writer may find the file missing or already there: whichever it is,
/// exactly one creates the file and no other overwrites it.
#[test]
fn racing_create_only_writers_create_exactly_once() {
    const WRITERS: usize = 8;
    const ROUNDS: usize = 200;
    let root = Root::new("race");

    for round in 0..ROUNDS {
        let barrier = Barrier::new(WRITERS);
        let outcomes: Outcomes = std::thread::scope(|scope| {
            let writers: Vec<_> = (0..WRITERS)
                .map(|writer| {
                    let (root, barrier) = (&root.0, &barrier);
                    scope.spawn(move || {
                        let kernel = kernel(root);
                        let content = format!("round {round} writer {writer}").into_bytes();
                        barrier.wait();
                        let result = sink_create_only(&kernel, "a.txt", &content);
                        (content, result)
                    })
                })
                .collect();
            writers.into_iter().map(|w| w.join().unwrap()).collect()
        });

        let winners: Vec<&Vec<u8>> = outcomes
            .iter()
            .filter(|(_, result)| result.is_ok())
            .map(|(content, _)| content)
            .collect();
        assert_eq!(winners.len(), 1, "round {round}: {outcomes:?}");
        assert_eq!(*winners[0], root.read("a.txt"), "round {round}");
        for (_, result) in &outcomes {
            assert!(
                matches!(result, Ok(()) | Err(Error::Conflict(_))),
                "round {round}: {result:?}"
            );
        }
        assert_eq!(root.names(), ["a.txt"], "round {round}");
        std::fs::remove_file(root.0.join("a.txt")).unwrap();
    }
}

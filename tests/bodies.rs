//! Bodies on the native backend (ledger #2245): a `Source` answers a seekable
//! `Replay` backed by the file, and a `Sink` writes its content chunk by chunk
//! through a staging file, so neither side holds a large file in memory.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures::executor::block_on;
use futures::StreamExt;
use ikigai_core::{
    ArgRef, Bindings, Body, ByteStream, Bytes, Capability, Endpoint, EndpointSpace, Error, Exact,
    FailureClass, Invocation, Iri, Kernel, ReprType, Representation, Request, Result, UriTemplate,
    Verb,
};
use ikigai_fs::{FileEndpoint, FILE_TEMPLATE, MAX_FILE_SOURCE_BYTES};

struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ikigai-fs-bodies-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Root(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Every name in the root other than `keep`: a staging file left behind shows here.
    fn strays(&self, keep: &str) -> Vec<String> {
        std::fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n != keep)
            .collect()
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// Bytes that are not UTF-8 and differ at every offset a chunk could start at.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 ^ 0x80).collect()
}

fn source_body(root: &Path, name: &str) -> Result<Representation<Body>> {
    let request = Request::new(
        Verb::Source,
        Iri::parse(format!("urn:file:{name}")).unwrap(),
    );
    let mut bindings = Bindings::new();
    bindings.insert("path", name);
    block_on(FileEndpoint::new(root).invoke_body(&Invocation::detached(
        &request,
        &bindings,
        &Capability::root(),
    )))
}

fn replay(root: &Path, name: &str) -> Arc<dyn ikigai_core::Replay> {
    match source_body(root, name).unwrap().bytes {
        Body::Replay(replay) => replay,
        other => panic!("expected a Replay body, got {other:?}"),
    }
}

/// Read a stream to its end, keeping every item (chunks and the error that ends it).
fn drain(stream: ByteStream) -> Vec<Result<Bytes>> {
    block_on(stream.collect::<Vec<_>>())
}

fn joined(items: Vec<Result<Bytes>>) -> Vec<u8> {
    items
        .into_iter()
        .flat_map(|item| item.unwrap().to_vec())
        .collect()
}

#[test]
fn a_source_body_is_a_replay_that_reads_the_same_bytes_twice() {
    let root = Root::new("twice");
    let bytes = pattern(200 * 1024 + 7);
    std::fs::write(root.path("data.bin"), &bytes).unwrap();

    let body = replay(&root.0, "data.bin");
    assert_eq!(body.len_hint(), Some(bytes.len() as u64));
    let first = drain(body.open());
    assert!(
        first.len() > 1,
        "a 200 KiB file is read in more than one chunk"
    );
    assert!(first.iter().all(|c| c.as_ref().unwrap().len() <= 64 * 1024));
    assert_eq!(joined(first), bytes);
    assert_eq!(joined(drain(body.open())), bytes);
}

#[test]
fn open_at_reads_the_suffix() {
    let root = Root::new("suffix");
    let bytes = pattern(100_000);
    std::fs::write(root.path("data.bin"), &bytes).unwrap();

    let body = replay(&root.0, "data.bin");
    for offset in [0u64, 1, 65_536, 99_999, 100_000] {
        let suffix = body.open_at(offset).expect("a file body is seekable");
        assert_eq!(joined(drain(suffix)), &bytes[offset as usize..], "{offset}");
    }
    assert!(joined(drain(body.open_at(200_000).unwrap())).is_empty());
}

#[test]
fn the_body_path_streams_past_the_bytes_bound() {
    let root = Root::new("large");
    let len = MAX_FILE_SOURCE_BYTES as usize + 1;
    std::fs::write(root.path("large.bin"), pattern(len)).unwrap();

    // The bytes path keeps its bound…
    let request = Request::new(Verb::Source, Iri::parse("urn:file:large.bin").unwrap());
    let mut bindings = Bindings::new();
    bindings.insert("path", "large.bin");
    let refused = block_on(FileEndpoint::new(&root.0).invoke(&Invocation::detached(
        &request,
        &bindings,
        &Capability::root(),
    )));
    assert!(
        matches!(refused, Err(Error::OverBudget { .. })),
        "{refused:?}"
    );

    // …and the body path streams the whole file without holding it.
    let answer = source_body(&root.0, "large.bin").unwrap();
    assert_eq!(answer.repr_type.media_type, "application/octet-stream");
    let Body::Replay(body) = answer.bytes else {
        panic!("expected a Replay body")
    };
    assert_eq!(body.len_hint(), Some(len as u64));
    let mut seen = 0usize;
    let mut stream = body.open();
    while let Some(chunk) = block_on(stream.next()) {
        let chunk = chunk.unwrap();
        assert!(chunk.len() <= 64 * 1024);
        seen += chunk.len();
    }
    assert_eq!(seen, len);
}

#[test]
fn a_body_keeps_the_media_type_rules_of_the_bytes_path() {
    let root = Root::new("types");
    std::fs::write(root.path("notes"), "café").unwrap();
    std::fs::write(root.path("blob"), [0xff, 0xfe]).unwrap();
    std::fs::write(root.path("page.md"), "# hi").unwrap();
    let ty = |name: &str| source_body(&root.0, name).unwrap().repr_type;
    assert_eq!(ty("notes").media_type, "text/plain");
    assert_eq!(ty("blob").media_type, "application/octet-stream");
    assert_eq!(ty("page.md").media_type, "text/markdown");
}

#[test]
fn a_file_changed_while_read_ends_the_stream_with_conflict() {
    let root = Root::new("torn");
    let path = root.path("data.bin");
    std::fs::write(&path, pattern(300_000)).unwrap();
    let body = replay(&root.0, "data.bin");

    // Changed in place while a reader is part-way: the reader ends in Conflict, never
    // as a short or mixed body taken for the whole.
    let mut stream = body.open();
    assert!(block_on(stream.next()).unwrap().is_ok());
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"grown").unwrap();
    }
    let rest = block_on(stream.collect::<Vec<_>>());
    assert!(
        matches!(rest.last(), Some(Err(Error::Conflict(m))) if m.contains("changed while read")),
        "{:?}",
        rest.last()
    );

    // Same size, rewritten in place (its timestamps moved): still refused.
    std::fs::write(&path, pattern(300_000)).unwrap();
    let body = replay(&root.0, "data.bin");
    let mut stream = body.open();
    assert!(block_on(stream.next()).unwrap().is_ok());
    {
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        std::os::unix::fs::FileExt::write_all_at(&file, b"XX", 0).unwrap();
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        file.set_modified(past).unwrap();
    }
    let rest = block_on(stream.collect::<Vec<_>>());
    assert!(
        matches!(rest.last(), Some(Err(Error::Conflict(_)))),
        "{:?}",
        rest.last()
    );

    // Changed between the body's open and a reader's: that reader is refused at once.
    let second = drain(body.open());
    assert!(
        matches!(second.as_slice(), [Err(Error::Conflict(_))]),
        "{second:?}"
    );
}

#[test]
fn a_reader_already_open_keeps_its_bytes_across_a_sink() {
    let root = Root::new("snapshot");
    let old = pattern(150_000);
    std::fs::write(root.path("data.bin"), &old).unwrap();
    let body = replay(&root.0, "data.bin");
    let mut open = body.open();
    let first = block_on(open.next()).unwrap().unwrap();

    let kernel = kernel(&root.0, vec![]);
    sink(&kernel, "data.bin", ArgRef::Inline(b"new".to_vec()), None).unwrap();

    let mut read = first.to_vec();
    read.extend(joined(block_on(open.collect::<Vec<_>>())));
    assert_eq!(read, old, "the open reader keeps the inode it opened");
    // A reader opened after the replacement is not handed the new file as the old one.
    assert!(matches!(
        drain(body.open()).as_slice(),
        [Err(Error::Conflict(_))]
    ));
}

#[test]
fn source_declares_the_conflict_its_body_can_end_with() {
    let description = FileEndpoint::new("/nonexistent").describe();
    for verb in [Verb::Source, Verb::Sink] {
        let action = description.actions.iter().find(|a| a.verb == verb).unwrap();
        assert!(
            action.failures.classes().is_some(),
            "{verb:?} states its failure classes"
        );
        // `Error::Conflict` is permanent.
        assert_eq!(
            Error::Conflict(String::new()).class(),
            FailureClass::Permanent
        );
        assert_eq!(action.admits_failure(FailureClass::Permanent), Some(true));
        assert_eq!(action.admits_failure(FailureClass::OverBudget), Some(true));
        assert_eq!(action.admits_failure(FailureClass::Unknown), Some(true));
    }
}

// --- streamed Sink -------------------------------------------------------------

/// A source of one-shot content: answers its chunks as a `Body::Once`, ending in
/// `fail` when one is set.
struct Chunks {
    chunks: Vec<&'static [u8]>,
    fail: bool,
}

#[async_trait]
impl Endpoint for Chunks {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let body = self.invoke_body(inv).await?;
        let bytes = inv.collect(body.bytes).await?;
        Ok(Representation::new(body.repr_type, bytes.to_vec()))
    }

    async fn invoke_body(&self, _inv: &Invocation<'_>) -> Result<Representation<Body>> {
        let mut items: Vec<Result<Bytes>> = self
            .chunks
            .iter()
            .map(|c| Ok(Bytes::from_static(c)))
            .collect();
        if self.fail {
            items.push(Err(Error::Unavailable("the producer went away".into())));
        }
        Ok(Representation::from_body(
            ReprType::new("application/octet-stream"),
            Body::once(futures::stream::iter(items)),
        ))
    }
}

fn kernel(root: &Path, sources: Vec<(&'static str, Chunks)>) -> Kernel {
    let space = sources.into_iter().fold(
        EndpointSpace::new().bind(
            UriTemplate::parse(FILE_TEMPLATE).unwrap(),
            FileEndpoint::new(root),
        ),
        |space, (iri, chunks)| space.bind(Exact::new(iri), chunks),
    );
    Kernel::new(Arc::new(space))
}

fn sink(
    kernel: &Kernel,
    name: &str,
    content: ArgRef,
    encoding: Option<&str>,
) -> Result<Representation> {
    let mut request = Request::new(Verb::Sink, Iri::parse(format!("urn:file:{name}")).unwrap())
        .with_arg("content", content);
    if let Some(encoding) = encoding {
        request = request.with_arg("encoding", ArgRef::Inline(encoding.as_bytes().to_vec()));
    }
    block_on(kernel.issue(request, &Capability::root()))
}

fn reference(iri: &str) -> ArgRef {
    ArgRef::Reference(Iri::parse(iri).unwrap())
}

#[test]
fn a_sink_from_a_multi_chunk_stream_lands_exactly() {
    let root = Root::new("sink");
    let kernel = kernel(
        &root.0,
        vec![
            // "café ☕" split inside both multi-byte characters.
            (
                "urn:gen:text",
                Chunks {
                    chunks: vec![b"caf", b"\xc3", b"\xa9 \xe2", b"\x98", b"\x95"],
                    fail: false,
                },
            ),
            // base64 of "hello, world!" split inside groups and inside the padding.
            (
                "urn:gen:base64",
                Chunks {
                    chunks: vec![b"aGV", b"sbG8sIHd", b"vcmxkIQ", b"=", b"="],
                    fail: false,
                },
            ),
        ],
    );

    let ack = sink(&kernel, "text.txt", reference("urn:gen:text"), None).unwrap();
    assert_eq!(
        std::fs::read(root.path("text.txt")).unwrap(),
        "café ☕".as_bytes()
    );
    assert_eq!(ack.bytes, b"wrote 9 bytes to text.txt");

    sink(
        &kernel,
        "data.bin",
        reference("urn:gen:base64"),
        Some("base64"),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(root.path("data.bin")).unwrap(),
        b"hello, world!"
    );
    assert!(root.strays("text.txt").iter().all(|n| n == "data.bin"));
}

#[test]
fn a_sink_whose_stream_fails_part_way_leaves_the_old_file() {
    let root = Root::new("sink-fail");
    std::fs::write(root.path("data.txt"), b"old").unwrap();
    let kernel = kernel(
        &root.0,
        vec![
            (
                "urn:gen:broken",
                Chunks {
                    chunks: vec![b"new ", b"content"],
                    fail: true,
                },
            ),
            (
                "urn:gen:not-utf8",
                Chunks {
                    chunks: vec![b"fine", b"\xff"],
                    fail: false,
                },
            ),
            (
                "urn:gen:cut-short",
                Chunks {
                    chunks: vec![b"caf\xc3"],
                    fail: false,
                },
            ),
            (
                "urn:gen:padding-mid-stream",
                Chunks {
                    chunks: vec![b"QQ==", b"QUFB"],
                    fail: false,
                },
            ),
        ],
    );

    let broken = sink(&kernel, "data.txt", reference("urn:gen:broken"), None);
    assert!(matches!(broken, Err(Error::Unavailable(_))), "{broken:?}");
    for (source, encoding) in [
        ("urn:gen:not-utf8", None),
        ("urn:gen:cut-short", None),
        ("urn:gen:padding-mid-stream", Some("base64")),
    ] {
        let refused = sink(&kernel, "data.txt", reference(source), encoding);
        assert!(
            matches!(&refused, Err(Error::InvalidArgument { name, .. }) if name == "content"),
            "{source}: {refused:?}"
        );
    }
    assert_eq!(std::fs::read(root.path("data.txt")).unwrap(), b"old");
    assert_eq!(
        root.strays("data.txt"),
        Vec::<String>::new(),
        "no staging file left"
    );

    // A new file whose stream fails is never created.
    let broken = sink(&kernel, "fresh.txt", reference("urn:gen:broken"), None);
    assert!(broken.is_err());
    assert!(!root.path("fresh.txt").exists());
    assert_eq!(root.strays("data.txt"), Vec::<String>::new());
}

#[test]
fn a_sink_by_reference_copies_a_file_past_the_bytes_bound_through_its_body() {
    let root = Root::new("copy");
    let bytes = pattern(MAX_FILE_SOURCE_BYTES as usize + 3);
    std::fs::write(root.path("from.bin"), &bytes).unwrap();
    std::fs::write(root.path("to.bin"), b"old").unwrap();
    let kernel = kernel(&root.0, vec![]);

    // The Sink reads the Source's `Replay` chunk by chunk: neither side is bound
    // by the bytes path's 16 MiB, and the content is never collected.
    let ack = sink(&kernel, "to.bin", reference("urn:file:from.bin"), None);
    // Not UTF-8, so the default encoding refuses it, and the old file stands.
    assert!(
        matches!(&ack, Err(Error::InvalidArgument { name, .. }) if name == "content"),
        "{ack:?}"
    );
    assert_eq!(std::fs::read(root.path("to.bin")).unwrap(), b"old");

    let text = "a line of text\n".repeat(MAX_FILE_SOURCE_BYTES as usize / 15 + 1);
    std::fs::write(root.path("from.txt"), &text).unwrap();
    let ack = sink(&kernel, "to.bin", reference("urn:file:from.txt"), None).unwrap();
    assert_eq!(
        ack.bytes,
        format!("wrote {} bytes to to.bin", text.len()).as_bytes()
    );
    assert_eq!(std::fs::read(root.path("to.bin")).unwrap(), text.as_bytes());
    let mut left = root.strays("from.bin");
    left.sort();
    assert_eq!(left, ["from.txt", "to.bin"]);
}

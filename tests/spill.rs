//! The file-backed spill facility (ledger #2241): [`FileSpill`] installed on a real
//! kernel with `with_spill`, driven through the sealed builtin `urn:stream:spill` under a
//! `urn:cap:stream:spill:<bytes>` grant.
#![cfg(unix)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures::executor::block_on;
use futures::StreamExt;
use ikigai_core::{
    cap_stream_spill, ArgRef, Body, ByteStream, Bytes, Capability, ContentId, Endpoint,
    EndpointSpace, Error, Exact, Invocation, Iri, Kernel, Replay, ReprType, Representation,
    Request, Result, Verb,
};
use ikigai_fs::{FileSpill, SPILL_PREFIX};

/// A spill directory of the test's own, under Cargo's scratch for integration tests.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "ikigai-fs-spill-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    /// Every name in the directory, sorted.
    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    /// The spill files in the directory.
    fn spills(&self) -> Vec<String> {
        self.names()
            .into_iter()
            .filter(|n| n.starts_with(SPILL_PREFIX))
            .collect()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// Bytes that differ at every offset a chunk could start at.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 ^ 0x5a).collect()
}

/// A source of one-shot content: answers its chunks as a `Body::once`, ending in an
/// error when `fail` is set.
struct Chunks {
    chunks: Vec<Bytes>,
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
        let mut items: Vec<Result<Bytes>> = self.chunks.iter().cloned().map(Ok).collect();
        if self.fail {
            items.push(Err(Error::Unavailable("the producer went away".into())));
        }
        Ok(Representation::from_body(
            ReprType::new("application/octet-stream"),
            Body::once(futures::stream::iter(items)),
        ))
    }
}

const SOURCE: &str = "urn:test:chunks";

/// A kernel with `FileSpill` over `dir` installed, and one source of one-shot content.
fn kernel(dir: &Scratch, chunks: Vec<Vec<u8>>, fail: bool) -> Kernel {
    let source = Chunks {
        chunks: chunks.into_iter().map(Bytes::from).collect(),
        fail,
    };
    let space = EndpointSpace::new().bind(Exact::new(SOURCE), source);
    Kernel::new(Arc::new(space)).with_spill(Arc::new(FileSpill::new(&dir.0).unwrap()))
}

/// Spill the source's body through `urn:stream:spill` under a grant of `granted` bytes.
fn spill(kernel: &Kernel, granted: u64) -> Result<Arc<dyn Replay>> {
    let request = Request::new(Verb::Source, Iri::parse("urn:stream:spill").unwrap())
        .with_arg("content", ArgRef::Reference(Iri::parse(SOURCE).unwrap()));
    let answer =
        block_on(kernel.issue_body(request, &Capability::scoped([cap_stream_spill(granted)])))?;
    match answer.bytes {
        Body::Replay(replay) => Ok(replay),
        other => panic!("a spill answers a Replay, got {other:?}"),
    }
}

/// Read a stream to its end, failing on any error.
fn read(stream: ByteStream) -> Vec<u8> {
    block_on(stream.collect::<Vec<_>>())
        .into_iter()
        .flat_map(|chunk| chunk.unwrap().to_vec())
        .collect()
}

/// Three chunks of the body, together past one 64 KiB reader chunk.
fn three_chunks() -> (Vec<Vec<u8>>, Vec<u8>) {
    let whole = pattern(150_000);
    let chunks = vec![
        whole[..1].to_vec(),
        whole[1..70_000].to_vec(),
        whole[70_000..].to_vec(),
    ];
    (chunks, whole)
}

#[test]
fn a_multi_chunk_body_spills_and_reads_back_twice() {
    let dir = Scratch::new("readback");
    let (chunks, whole) = three_chunks();
    let kernel = kernel(&dir, chunks, false);
    let replay = spill(&kernel, whole.len() as u64).unwrap();

    assert_eq!(replay.len_hint(), Some(whole.len() as u64));
    assert_eq!(replay.validator(), Some(ContentId::of(&whole)));
    // Two readers, each the whole body, each in bounded chunks.
    for _ in 0..2 {
        let chunks: Vec<Bytes> = block_on(replay.open().collect::<Vec<_>>())
            .into_iter()
            .map(|c| c.unwrap())
            .collect();
        assert!(
            chunks.len() > 1,
            "150 000 bytes read in more than one chunk"
        );
        assert!(chunks.iter().all(|c| c.len() <= 64 * 1024));
        assert_eq!(chunks.concat(), whole);
    }
}

#[test]
fn open_at_gives_the_suffix() {
    let dir = Scratch::new("open-at");
    let (chunks, whole) = three_chunks();
    let kernel = kernel(&dir, chunks, false);
    let replay = spill(&kernel, whole.len() as u64).unwrap();

    for offset in [0, 1, 65_536, 100_000, whole.len() - 1] {
        let suffix = read(replay.open_at(offset as u64).expect("a spill is seekable"));
        assert_eq!(suffix, whole[offset..], "from byte {offset}");
    }
    assert!(read(replay.open_at(whole.len() as u64).unwrap()).is_empty());
    assert!(read(replay.open_at(whole.len() as u64 + 10).unwrap()).is_empty());
}

#[test]
fn the_file_lives_while_held_and_goes_with_the_last_holder() {
    let dir = Scratch::new("lifetime");
    let (chunks, whole) = three_chunks();
    let kernel = kernel(&dir, chunks, false);
    let replay = spill(&kernel, whole.len() as u64).unwrap();

    let held = dir.spills();
    assert_eq!(held.len(), 1, "one spill file while the answer is held");
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(dir.0.join(&held[0]))
            .unwrap()
            .permissions(),
    );
    assert_eq!(mode & 0o777, 0o600, "owner only");

    // A second holder keeps it; a reader opened before the last drop finishes after it.
    let second = replay.clone();
    drop(replay);
    assert_eq!(dir.spills(), held);
    let mut reader = second.open();
    let first = block_on(reader.next()).unwrap().unwrap();
    // The kernel may hold the answer in its cache too: it is a holder like any other.
    drop(kernel);
    drop(second);
    assert!(dir.spills().is_empty(), "removed with the last holder");

    let mut read_back = first.to_vec();
    read_back.extend(read(reader));
    assert_eq!(read_back, whole, "an open reader finishes after the unlink");
}

#[test]
fn one_byte_past_the_grant_is_over_budget_and_leaves_no_file() {
    let dir = Scratch::new("over");
    let (chunks, whole) = three_chunks();
    let kernel = kernel(&dir, chunks, false);
    match spill(&kernel, whole.len() as u64 - 1) {
        Err(Error::OverBudget { .. }) => {}
        Err(other) => panic!("expected OverBudget, got {other:?}"),
        Ok(_) => panic!("expected OverBudget, got a body"),
    }
    assert!(dir.spills().is_empty(), "no file left behind");
}

#[test]
fn exactly_at_the_grant_is_accepted() {
    let dir = Scratch::new("exact");
    let (chunks, whole) = three_chunks();
    let kernel = kernel(&dir, chunks, false);
    let replay = spill(&kernel, whole.len() as u64).unwrap();
    assert_eq!(read(replay.open()), whole);
}

#[test]
fn the_facility_itself_stops_at_max_bytes() {
    // Called directly with a body that states no length, so core's own pre-check of a
    // stated length cannot be what refuses it.
    let dir = Scratch::new("direct");
    let facility = FileSpill::new(&dir.0).unwrap();
    let body = |n: usize| -> ByteStream {
        Box::pin(futures::stream::iter(
            pattern(n)
                .chunks(7)
                .map(|c| Ok(Bytes::from(c.to_vec())))
                .collect::<Vec<_>>(),
        ))
    };
    match block_on(ikigai_core::Spill::spill(&facility, body(101), 100)) {
        Err(Error::OverBudget { .. }) => {}
        Err(other) => panic!("expected OverBudget, got {other:?}"),
        Ok(_) => panic!("expected OverBudget, got a body"),
    }
    assert!(dir.spills().is_empty());
    let replay = block_on(ikigai_core::Spill::spill(&facility, body(100), 100)).unwrap();
    assert_eq!(read(replay.open()), pattern(100));
    assert_eq!(replay.validator(), Some(ContentId::of(&pattern(100))));
    drop(replay);
    assert!(dir.spills().is_empty());
}

#[test]
fn a_body_that_errors_midway_leaves_no_file() {
    let dir = Scratch::new("error");
    let (chunks, whole) = three_chunks();
    let kernel = kernel(&dir, chunks, true);
    match spill(&kernel, whole.len() as u64 * 2) {
        Err(Error::Unavailable(detail)) => assert!(detail.contains("went away"), "{detail}"),
        Err(other) => panic!("expected the body's own error, got {other:?}"),
        Ok(_) => panic!("expected the body's own error, got a body"),
    }
    assert!(dir.spills().is_empty(), "no file left behind");
}

#[test]
fn new_removes_stale_spill_files_and_nothing_else() {
    let dir = Scratch::new("orphans");
    let stale = [
        format!("{SPILL_PREFIX}00000000000000000000000000000000"),
        format!("{SPILL_PREFIX}ffffffffffffffffffffffffffffffff"),
    ];
    for name in &stale {
        std::fs::write(dir.0.join(name), b"left by a killed process").unwrap();
    }
    let others = [
        ".ikigai-spill",
        ".ikigai-fs-0123.tmp",
        "ikigai-spill-not-hidden",
        "notes.txt",
    ];
    for name in others {
        std::fs::write(dir.0.join(name), b"keep me").unwrap();
    }
    // A prefixed directory is not a spill file either.
    let prefixed_dir = format!("{SPILL_PREFIX}dir");
    std::fs::create_dir(dir.0.join(&prefixed_dir)).unwrap();

    let _facility = FileSpill::new(&dir.0).unwrap();

    let mut expected: Vec<String> = others.iter().map(|n| n.to_string()).collect();
    expected.push(prefixed_dir);
    expected.sort();
    assert_eq!(dir.names(), expected);
    for name in others {
        assert_eq!(std::fs::read(dir.0.join(name)).unwrap(), b"keep me");
    }
}

#[test]
fn new_refuses_a_missing_directory() {
    let dir = Scratch::new("missing");
    let missing = dir.0.join("not-there");
    assert!(FileSpill::new(&missing).is_err());
    assert!(!missing.exists(), "the directory is never created");
}

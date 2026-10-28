//! **A root's write ceiling** (ledger #2493): since the Sink reads `content` as a body
//! (ledger #2469), a piped write streams to disk and is never collected under the run's byte
//! budget, so the root bounds it instead: `FileEndpoint::max_write`, [`DEFAULT_MAX_WRITE`]
//! unless set. Counted after decoding, the same for every way content arrives, and refused
//! with nothing left behind.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;

use futures::executor::block_on;
use futures::StreamExt;
use ikigai_core::{
    ArgRef, Body, BodyIssue, Bytes, Capability, EndpointSpace, Error, Iri, Kernel,
    MemoryContentStore, Request, Result, UriTemplate, Verb,
};
use ikigai_fs::{FileEndpoint, DEFAULT_MAX_WRITE, FILE_TEMPLATE};

struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "ikigai-fs-max-write-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        Root(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
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

const CEILING: u64 = 16;

fn kernel(root: &Path, store: Arc<MemoryContentStore>) -> Kernel {
    let space = EndpointSpace::new().bind(
        UriTemplate::parse(FILE_TEMPLATE).unwrap(),
        FileEndpoint::new(root).max_write(CEILING),
    );
    Kernel::new(Arc::new(space)).with_content_store(store)
}

fn sink_request(name: &str, encoding: Option<&str>) -> Request {
    let request = Request::new(Verb::Sink, Iri::parse(format!("urn:file:{name}")).unwrap());
    match encoding {
        Some(e) => request.with_arg("encoding", ArgRef::Inline(e.as_bytes().to_vec())),
        None => request,
    }
}

/// The content three ways: inline, a `b3:` content id, and an attached body in 5-byte chunks.
fn write_every_way(
    kernel: &Kernel,
    store: &MemoryContentStore,
    content: &[u8],
    encoding: Option<&str>,
) -> [Result<()>; 3] {
    let cap = Capability::root();
    let inline = block_on(kernel.issue(
        sink_request("inline", encoding).with_arg("content", ArgRef::Inline(content.to_vec())),
        &cap,
    ));
    let held = store.put(content.to_vec()).unwrap();
    let by_id = block_on(kernel.issue(
        sink_request("by-id", encoding).with_arg("content", ArgRef::Content(held.id())),
        &cap,
    ));
    let chunks: Vec<Result<Bytes>> = content
        .chunks(5)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let body = Body::once(futures::stream::iter(chunks));
    let attached = block_on(kernel.issue_with(
        sink_request("attached", encoding),
        &cap,
        BodyIssue::new().attach("content", body),
    ));
    [inline.map(|_| ()), by_id.map(|_| ()), attached.map(|_| ())]
}

#[test]
fn the_default_ceiling_is_the_wires_upload_bound() {
    assert_eq!(DEFAULT_MAX_WRITE, 64 << 20);
}

/// Exactly the ceiling is written, every way, and base64 counts the DECODED bytes: 16 bytes
/// encoded as 24 characters fit a 16-byte ceiling.
#[test]
fn content_at_the_ceiling_is_written_counted_after_decoding() {
    let root = Root::new("at");
    let store = Arc::new(MemoryContentStore::new(1 << 20));
    let kernel = kernel(&root.0, store.clone());
    let exact = b"sixteen bytes!!\n";
    assert_eq!(exact.len() as u64, CEILING);

    for (content, encoding) in [
        (exact.to_vec(), None),
        (b"c2l4dGVlbiBieXRlcyEhCg==".to_vec(), Some("base64")),
    ] {
        for (way, result) in ["inline", "by-id", "attached"]
            .iter()
            .zip(write_every_way(&kernel, &store, &content, encoding))
        {
            result.unwrap_or_else(|e| panic!("{way} {encoding:?}: {e}"));
            assert_eq!(std::fs::read(root.path(way)).unwrap(), exact, "{way}");
        }
    }
    assert_eq!(root.names(), ["attached", "by-id", "inline"]);
}

/// One byte past is refused with `OverBudget` every way, never a shorter file: the old target
/// stays where there was one, none appears where there was none, and no staging file is left.
#[test]
fn one_byte_past_the_ceiling_is_refused_with_nothing_left_behind() {
    let root = Root::new("past");
    let store = Arc::new(MemoryContentStore::new(1 << 20));
    let kernel = kernel(&root.0, store.clone());
    std::fs::write(root.path("inline"), b"old").unwrap();
    let past = b"seventeen bytes!\n";
    assert_eq!(past.len() as u64, CEILING + 1);

    for (way, result) in ["inline", "by-id", "attached"]
        .iter()
        .zip(write_every_way(&kernel, &store, past, None))
    {
        match result {
            Err(Error::OverBudget { detail }) => {
                assert!(detail.contains("16-byte ceiling"), "{way}: {detail}")
            }
            other => panic!("{way}: {other:?}"),
        }
    }
    assert_eq!(std::fs::read(root.path("inline")).unwrap(), b"old");
    assert_eq!(root.names(), ["inline"], "no new target, no staging file");
}

/// A streamed write is refused PART-WAY: the Sink stops pulling the body at the chunk that
/// crosses the ceiling, so an endless producer cannot fill the disk.
#[test]
fn an_endless_body_is_refused_at_the_ceiling_without_being_drained() {
    let root = Root::new("endless");
    let kernel = kernel(&root.0, Arc::new(MemoryContentStore::new(1 << 20)));
    let pulled = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&pulled);
    let endless = Body::once(futures::stream::repeat(()).map(move |()| {
        count.fetch_add(1, Ordering::Relaxed);
        Ok(Bytes::from_static(b"12345"))
    }));
    let refused = block_on(kernel.issue_with(
        sink_request("out.txt", None),
        &Capability::root(),
        BodyIssue::new().attach("content", endless),
    ));
    assert!(
        matches!(refused, Err(Error::OverBudget { .. })),
        "{:?}",
        refused.map(|_| ())
    );
    // 5-byte chunks cross 16 bytes on the fourth.
    assert_eq!(pulled.load(Ordering::Relaxed), 4);
    assert_eq!(root.names(), Vec::<String>::new());
}

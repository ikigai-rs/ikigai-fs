//! A file body states a strong validator (ledger #2474): the content id of its bytes,
//! hashed once per version of the file and remembered against that version, so the web
//! door gives a large file an `ETag`, `304` and byte ranges.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::executor::block_on;
use ikigai_core::{
    Bindings, Body, Capability, ContentId, Endpoint, EndpointSpace, Invocation, Iri, Kernel,
    Replay, Request, UriTemplate, Verb,
};
use ikigai_fs::{FileEndpoint, FILE_TEMPLATE, VALIDATOR_SETTLE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ikigai-fs-validator-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Root(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// Bytes that are not UTF-8 and differ at every offset a chunk could start at.
fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i % 251) as u8 ^ 0x80).wrapping_add(salt))
        .collect()
}

fn replay(root: &Path, name: &str) -> Arc<dyn Replay> {
    let request = Request::new(
        Verb::Source,
        Iri::parse(format!("urn:file:{name}")).unwrap(),
    );
    let mut bindings = Bindings::new();
    bindings.insert("path", name);
    let body = block_on(FileEndpoint::new(root).invoke_body(&Invocation::detached(
        &request,
        &bindings,
        &Capability::root(),
    )))
    .unwrap();
    match body.bytes {
        Body::Replay(replay) => replay,
        other => panic!("expected a Replay body, got {other:?}"),
    }
}

/// Past the window in which a just-written file's timestamps cannot yet tell a second
/// write apart from the first.
fn settle() {
    std::thread::sleep(VALIDATOR_SETTLE + Duration::from_millis(100));
}

#[test]
fn a_file_body_states_the_content_id_of_its_bytes() {
    let root = Root::new("same");
    let bytes = pattern(300 * 1024 + 3, 0);
    std::fs::write(root.path("data.bin"), &bytes).unwrap();
    settle();

    let first = replay(&root.0, "data.bin");
    assert_eq!(first.validator(), Some(ContentId::of(&bytes)));
    assert_eq!(
        first.validator(),
        Some(ContentId::of(&bytes)),
        "asked twice"
    );
    // A second body over the same, unchanged file: the same validator.
    assert_eq!(
        replay(&root.0, "data.bin").validator(),
        Some(ContentId::of(&bytes))
    );
}

#[test]
fn a_same_length_rewrite_changes_the_validator() {
    let root = Root::new("rewrite");
    let before = pattern(200 * 1024, 0);
    let after = pattern(200 * 1024, 1);
    std::fs::write(root.path("data.bin"), &before).unwrap();
    settle();
    let old = replay(&root.0, "data.bin").validator();
    assert_eq!(old, Some(ContentId::of(&before)));

    // Rewritten in place (same inode, same length), then its mtime put back: only the
    // ctime tells the versions apart, and the remembered digest must not be reused.
    let mtime = std::fs::metadata(root.path("data.bin"))
        .unwrap()
        .modified()
        .unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(root.path("data.bin"))
        .unwrap();
    std::os::unix::fs::FileExt::write_all_at(&file, &after, 0).unwrap();
    file.set_modified(mtime).unwrap();
    drop(file);
    settle();

    let new = replay(&root.0, "data.bin").validator();
    assert_eq!(new, Some(ContentId::of(&after)));
    assert_ne!(new, old);
}

#[test]
fn a_file_written_a_moment_ago_states_no_validator_yet() {
    let root = Root::new("fresh");
    std::fs::write(root.path("data.bin"), pattern(1000, 0)).unwrap();
    // Its timestamps could not yet tell a second same-length write in the same tick
    // apart, so no digest is stated (or remembered) for it.
    assert_eq!(replay(&root.0, "data.bin").validator(), None);
}

/// Send `raw` to the door at `addr` and read the whole answer.
async fn send(addr: std::net::SocketAddr, raw: &str) -> Vec<u8> {
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    c.write_all(raw.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).await.unwrap();
    out
}

/// The head (as text) and the body of an answer.
fn split(answer: &[u8]) -> (String, &[u8]) {
    let at = answer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head");
    (
        String::from_utf8_lossy(&answer[..at]).into_owned(),
        &answer[at + 4..],
    )
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn the_door_answers_a_range_of_a_large_file() {
    let root = Root::new("door");
    let bytes = pattern(2 * 1024 * 1024, 0);
    std::fs::write(root.path("big.bin"), &bytes).unwrap();
    settle();

    let space = EndpointSpace::new().bind(
        UriTemplate::parse(FILE_TEMPLATE).unwrap(),
        FileEndpoint::new(&root.0),
    );
    let kernel = Arc::new(Kernel::new(Arc::new(space)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(ikigai_web::serve_with_listener(
        kernel,
        // The jail and its path-ACL are what this test is not about: every request may read.
        Arc::new(|_: &ikigai_web::HttpRequest| Capability::root()),
        listener,
        ikigai_web::EdgeConfig::default(),
    ));
    let get = |extra: String| {
        format!("GET /file/big.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}\r\n")
    };

    let whole = send(addr, &get(String::new())).await;
    let (head, body) = split(&whole);
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert_eq!(header(&head, "accept-ranges"), Some("bytes"), "{head}");
    let etag = header(&head, "etag")
        .unwrap_or_else(|| panic!("a 2 MiB file has an ETag: {head}"))
        .to_string();
    assert!(!etag.starts_with("W/"), "a strong validator: {etag}");
    assert_eq!(body, &bytes[..]);

    let (first, last) = (1_500_000usize, 1_600_009usize);
    let ranged = send(addr, &get(format!("Range: bytes={first}-{last}\r\n"))).await;
    let (head, body) = split(&ranged);
    assert!(head.starts_with("HTTP/1.1 206 "), "{head}");
    assert_eq!(
        header(&head, "content-range"),
        Some(format!("bytes {first}-{last}/{}", bytes.len()).as_str()),
        "{head}"
    );
    assert_eq!(body, &bytes[first..=last]);

    let same = send(
        addr,
        &get(format!("Range: bytes=0-9\r\nIf-Range: {etag}\r\n")),
    )
    .await;
    assert!(split(&same).0.starts_with("HTTP/1.1 206 "));

    let unchanged = send(addr, &get(format!("If-None-Match: {etag}\r\n"))).await;
    assert!(
        split(&unchanged).0.starts_with("HTTP/1.1 304 "),
        "{}",
        split(&unchanged).0
    );
}

//! **The Sink reads `content` as a body** (ledger #2469, after core's #2402): its contract
//! declares `ArgSpec::reads_body` on `content`, so a body a host attaches
//! (`BodyIssue::attach`, what `| sink urn:file:x` runs through) streams into the staging
//! file instead of being collected by the kernel first.
//!
//! The reproduction comes first: on ikigai-fs 0.2.2 the kernel collected an attached body
//! under the run's byte budget before entering the Sink, so the producer ran to its end
//! before anything was staged, and a body past the budget was refused although the Sink
//! never needed to hold it.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use futures::StreamExt;
use ikigai_core::{
    ActionSpec, ArgRef, Body, BodyIssue, Bytes, Capability, Endpoint, EndpointSpace, Error, Iri,
    IssueContext, Kernel, MemoryContentStore, Representation, Request, Result, TraceEvent, Tracer,
    UriTemplate, Verb, COLLECTED_NOTE,
};
use ikigai_fs::{FileEndpoint, FileSpill, FILE_TEMPLATE};

struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "ikigai-fs-reads-body-{}-{name}-{}",
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
        names(&self.0)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn kernel(root: &Path) -> Kernel {
    let space = EndpointSpace::new().bind(
        UriTemplate::parse(FILE_TEMPLATE).unwrap(),
        FileEndpoint::new(root),
    );
    Kernel::new(Arc::new(space))
}

fn sink_request(name: &str) -> Request {
    Request::new(Verb::Sink, Iri::parse(format!("urn:file:{name}")).unwrap())
}

/// `| sink urn:file:{name}`: `body` attached as `content`, as an engine pipes a stage.
fn sink_attached(kernel: &Kernel, name: &str, issue: BodyIssue, body: Body) -> Result<Vec<u8>> {
    let issue = issue.attach("content", body);
    block_on(kernel.issue_with(sink_request(name), &Capability::root(), issue))
        .map(|answer: Representation| answer.bytes)
}

/// A one-shot body of `chunks`, ending in `fail` when one is given.
fn once(chunks: &[&'static [u8]], fail: Option<Error>) -> Body {
    let mut items: Vec<Result<Bytes>> = chunks.iter().map(|c| Ok(Bytes::from_static(c))).collect();
    items.extend(fail.map(Err));
    Body::once(futures::stream::iter(items))
}

#[derive(Default)]
struct Collect(Mutex<Vec<TraceEvent>>);

impl Tracer for Collect {
    fn record(&self, event: TraceEvent) {
        self.0.lock().unwrap().push(event);
    }
}

impl Collect {
    fn collected(&self, target: &str) -> Option<String> {
        let events = self.0.lock().unwrap();
        let event = events.iter().rev().find(|e| e.target == target)?;
        event
            .notes
            .iter()
            .find(|(k, _)| k == COLLECTED_NOTE)
            .map(|(_, v)| v.clone())
    }
}

/// The Sink action's spec, as the endpoint describes it.
fn sink_action() -> ActionSpec {
    FileEndpoint::new(std::env::temp_dir())
        .describe()
        .action_specs()
        .into_iter()
        .find(|a| a.verb == Verb::Sink)
        .unwrap()
}

/// The contract: `content` is declared read as a body on the Sink action (and only there),
/// and that moves the Sink's contract IRI away from the by-value one 0.2.2 published.
#[test]
fn the_sink_declares_content_read_as_a_body_and_its_contract_iri_moves() {
    let sink = sink_action();
    let content = sink.inputs.iter().find(|i| i.name == "content").unwrap();
    assert!(content.reads_body, "Sink's `content` is read as a body");
    let readers: Vec<&str> = sink
        .inputs
        .iter()
        .filter(|i| i.reads_body)
        .map(|i| i.name.as_str())
        .collect();
    assert_eq!(readers, ["content"]);
    let description = FileEndpoint::new(std::env::temp_dir()).describe();
    assert!(description.validate().is_ok());
    for action in description.action_specs() {
        if action.verb != Verb::Sink {
            assert!(
                action.inputs.iter().all(|i| !i.reads_body),
                "{:?}",
                action.verb
            );
        }
    }

    // The same action with `content` by value is the 0.2.2 contract: another IRI.
    let mut by_value = sink.clone();
    for input in &mut by_value.inputs {
        input.reads_body = false;
    }
    assert_ne!(sink.contract_iri("file"), by_value.contract_iri("file"));
}

/// The reproduction: a body attached to the Sink is staged while the producer is still
/// producing (the staging file is in the root as each chunk is made), the kernel
/// collects nothing, and a body past the run's byte budget is written, because the Sink
/// never holds it. On 0.2.2 the kernel collected it first: no staging file until the
/// producer ended, `collected=content` in the trace, and `OverBudget` past the budget.
#[test]
fn an_attached_body_streams_to_disk_and_is_not_collected_by_the_kernel() {
    let root = Root::new("stream");
    let kernel = kernel(&root.0);
    const CHUNKS: usize = 8;
    let seen: Arc<Mutex<Vec<Vec<String>>>> = Arc::default();
    let dir = root.0.clone();
    let log = Arc::clone(&seen);
    let producer = Body::once(futures::stream::iter(0..CHUNKS).map(move |i| {
        // What is on disk as chunk `i` is produced.
        log.lock().unwrap().push(names(&dir));
        Ok(Bytes::from(format!("chunk {i}\n")))
    }));
    let tracer = Arc::new(Collect::default());
    let issue = BodyIssue::new()
        .traced(tracer.clone())
        .with_context(IssueContext::new().with_memory_limit(16));
    let ack = sink_attached(&kernel, "out.txt", issue, producer).unwrap();

    let expected: String = (0..CHUNKS).map(|i| format!("chunk {i}\n")).collect();
    assert_eq!(
        std::fs::read(root.path("out.txt")).unwrap(),
        expected.as_bytes()
    );
    assert_eq!(
        ack,
        format!("wrote {} bytes to out.txt", expected.len()).as_bytes()
    );
    assert!(
        expected.len() > 16,
        "the body is past the run's 16-byte budget"
    );
    assert_eq!(
        tracer.collected("urn:file:out.txt"),
        None,
        "the kernel collected nothing"
    );
    let seen = seen.lock().unwrap();
    // Collected first, the root would be empty as every chunk was produced: the Sink is
    // entered only after the producer ends.
    for (i, on_disk) in seen.iter().enumerate() {
        assert!(
            on_disk.len() == 1 && on_disk[0].ends_with(".tmp"),
            "the staging file is open while chunk {i} is produced: {seen:?}"
        );
    }
    assert_eq!(root.names(), ["out.txt"], "no staging file left");
}

/// Inline bytes, a `b3:` content id from the kernel's store, a live attached body and a
/// spilled body attached write identical files, for UTF-8 text and for base64.
#[test]
fn inline_a_content_id_and_an_attached_body_write_identical_files() {
    let root = Root::new("forms");
    let spill_dir = Root::new("forms-spill");
    let store = Arc::new(MemoryContentStore::new(1 << 20));
    let kernel = kernel(&root.0)
        .with_content_store(store.clone())
        .with_spill(Arc::new(FileSpill::new(&spill_dir.0).unwrap()))
        .with_stream_spill(0, 1 << 20);
    let cap = Capability::root();

    for (content, encoding, written) in [
        (
            "café ☕ — a line of text\n".repeat(50).into_bytes(),
            None,
            "café ☕ — a line of text\n".repeat(50).into_bytes(),
        ),
        (
            b"aGVsbG8sIHdvcmxkIQ==".to_vec(),
            Some("base64"),
            b"hello, world!".to_vec(),
        ),
    ] {
        let with_encoding = |request: Request| match encoding {
            Some(e) => request.with_arg("encoding", ArgRef::Inline(e.as_bytes().to_vec())),
            None => request,
        };
        let issue = |request: Request| block_on(kernel.issue(with_encoding(request), &cap));

        issue(sink_request("inline").with_arg("content", ArgRef::Inline(content.clone()))).unwrap();
        let held = store.put(content.clone()).unwrap();
        assert!(held.id().to_string().starts_with("b3:"));
        issue(sink_request("by-id").with_arg("content", ArgRef::Content(held.id()))).unwrap();

        // Live: in uneven chunks that split characters and base64 groups.
        let chunks: Vec<Result<Bytes>> = content
            .chunks(7)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let live = Body::once(futures::stream::iter(chunks));
        let attached = |name: &str, body: Body| {
            let issue = BodyIssue::new().attach("content", body);
            block_on(kernel.issue_with(with_encoding(sink_request(name)), &cap, issue)).unwrap()
        };
        attached("live", live);

        // Spilled first, then attached under its digest.
        let spill = Request::new(Verb::Source, Iri::parse("urn:stream:spill").unwrap());
        let spilled = block_on(kernel.issue_body_with(
            spill,
            &cap,
            BodyIssue::new().attach("content", Body::from(content.clone())),
        ))
        .unwrap();
        attached("spilled", spilled.bytes);

        for name in ["inline", "by-id", "live", "spilled"] {
            assert_eq!(std::fs::read(root.path(name)).unwrap(), written, "{name}");
        }
        assert_eq!(root.names(), ["by-id", "inline", "live", "spilled"]);
    }
}

/// A body past a budget is refused, never a shorter file, and leaves nothing behind: no
/// target where there was none, the old target where there was one, no staging file.
///
/// Streaming moves the refusal: the kernel no longer refuses before the Sink starts, so the
/// budgeted producer's refusal now arrives part-way through the write, after the staging
/// file exists. The memory case is a producer that ends in `OverBudget` once it has handed
/// over what fitted (what a budgeted stage answers); the disk case is a real one, a live
/// body spilled under too small a disk grant, with the spill directory left empty too.
#[test]
fn a_body_past_the_memory_or_disk_budget_is_refused_with_nothing_left_behind() {
    let root = Root::new("budget");
    let spill_dir = Root::new("budget-spill");
    std::fs::write(root.path("old.txt"), b"old").unwrap();
    let kernel = kernel(&root.0)
        .with_spill(Arc::new(FileSpill::new(&spill_dir.0).unwrap()))
        .with_stream_spill(0, 8);
    let past_memory = || {
        once(
            &[b"first ", b"second "],
            Some(Error::OverBudget {
                detail: "past the run's byte budget".into(),
            }),
        )
    };

    for name in ["old.txt", "new.txt"] {
        let refused = sink_attached(&kernel, name, BodyIssue::new(), past_memory());
        assert!(
            matches!(refused, Err(Error::OverBudget { .. })),
            "{name}: {refused:?}"
        );
    }
    assert_eq!(std::fs::read(root.path("old.txt")).unwrap(), b"old");
    assert_eq!(
        root.names(),
        ["old.txt"],
        "no target created, no staging file"
    );

    // Disk: the spill refuses past its 8-byte ceiling, so nothing reaches the Sink.
    let spill = Request::new(Verb::Source, Iri::parse("urn:stream:spill").unwrap());
    let refused = block_on(kernel.issue_body_with(
        spill,
        &Capability::root(),
        BodyIssue::new().attach("content", once(&[b"first ", b"second "], None)),
    ));
    assert!(
        matches!(refused, Err(Error::OverBudget { .. })),
        "{:?}",
        refused.map(|_| ())
    );
    assert_eq!(
        names(&spill_dir.0),
        Vec::<String>::new(),
        "no spill file left"
    );
    assert_eq!(root.names(), ["old.txt"]);
}

/// A by-value argument stays by value: `encoding` is not declared a body reader, so a body
/// attached to it is collected by the kernel and handed over inline, as before.
#[test]
fn encoding_is_still_collected() {
    let root = Root::new("encoding");
    let kernel = kernel(&root.0);
    let tracer = Arc::new(Collect::default());
    let request =
        sink_request("data.bin").with_arg("content", ArgRef::Inline(b"AP/+gA==".to_vec()));
    let issue = BodyIssue::new()
        .traced(tracer.clone())
        .attach("encoding", once(&[b"base", b"64"], None));
    block_on(kernel.issue_with(request, &Capability::root(), issue)).unwrap();
    assert_eq!(
        std::fs::read(root.path("data.bin")).unwrap(),
        [0, 255, 254, 128]
    );
    assert_eq!(
        tracer.collected("urn:file:data.bin").as_deref(),
        Some("encoding")
    );
}

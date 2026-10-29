//! Disposable research harness; never enables caching in the real endpoint.
use futures::executor::block_on;
use ikigai_core::{
    ArgRef, AsyncFnEndpoint, Bindings, Capability, ContentId, Endpoint, EndpointSpace, Exact,
    FixedClock, FnEndpoint, Invocation, Iri, Kernel, OriginValidator, ReprType, Representation,
    Request, UriTemplate, Verb,
};
use ikigai_fs::FileEndpoint;
use notify::{RecursiveMode, Watcher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    fs,
    hint::black_box,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

fn request(verb: Verb, path: &str) -> Request {
    Request::new(verb, Iri::parse(format!("urn:file:{path}")).unwrap())
}

fn list(endpoint: &FileEndpoint) -> Representation {
    let req = request(Verb::Source, "listing");
    let cap = Capability::root();
    let mut bindings = Bindings::new();
    bindings.insert("path", "listing");
    block_on(endpoint.invoke(&Invocation::detached(&req, &bindings, &cap))).unwrap()
}

fn measure(label: &str, n: usize, samples: usize, mut op: impl FnMut()) {
    for _ in 0..5 {
        op();
    }
    let mut times = Vec::new();
    for _ in 0..samples {
        let start = Instant::now();
        op();
        times.push(start.elapsed().as_nanos());
    }
    times.sort_unstable();
    println!(
        "{label},{n},{samples},{},{},{}",
        times[0],
        times[samples / 2],
        times[(samples - 1) * 95 / 100]
    );
}

fn bench(root: &Path) {
    println!("operation,entries,samples,min_ns,median_ns,p95_ns");
    for n in [10, 1_000, 100_000] {
        let base = root.join(n.to_string());
        let dir = base.join("listing");
        fs::create_dir_all(&dir).unwrap();
        for i in 0..n {
            fs::write(dir.join(format!("file-{i:06}.rq")), b"x").unwrap();
        }
        let ep = FileEndpoint::new(&base);
        assert_eq!(list(&ep).bytes.split(|b| *b == b'\n').count(), n);
        let samples = if n == 100_000 { 51 } else { 501 };
        measure("stat-path-warm", n, samples, || {
            black_box(fs::metadata(&dir).unwrap());
        });
        let handle = fs::File::open(&dir).unwrap();
        measure("fstat-handle-warm", n, samples, || {
            black_box(handle.metadata().unwrap());
        });
        measure("enumerate-sort-warm", n, samples, || {
            let mut names: Vec<_> = fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            names.sort_unstable();
            black_box(names);
        });
        measure("endpoint-list-warm", n, samples, || {
            black_box(list(&ep));
        });
        measure("endpoint-list-hash-warm", n, samples, || {
            black_box(ContentId::of(&list(&ep).bytes));
        });
        let held = list(&ep);
        measure("hash-held-bytes-warm", n, samples, || {
            black_box(ContentId::of(&held.bytes));
        });
        // An intentionally frozen answer measures the kernel's best-case cache
        // hit, including copying the answer; it is NOT a safe filesystem cache.
        let frozen = FnEndpoint::new("frozen-listing", move |_| Ok(held.clone().cacheable()));
        let cached = Kernel::new(Arc::new(
            EndpointSpace::new().bind(UriTemplate::parse("urn:file:{path}").unwrap(), frozen),
        ));
        measure("kernel-hit-unsafe-warm", n, samples, || {
            black_box(
                block_on(cached.issue(request(Verb::Source, "listing"), &Capability::root()))
                    .unwrap(),
            );
        });
        let kernel = Kernel::new(Arc::new(ikigai_fs::cacheable_space(&base)));
        measure("kernel-list-warm", n, samples, || {
            black_box(
                block_on(kernel.issue(request(Verb::Source, "listing"), &Capability::root()))
                    .unwrap(),
            );
        });
    }
}

fn reproduce(root: &Path) {
    let dir = root.join("listing");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("a"), b"a").unwrap();
    let cap = Capability::root();
    let current = Kernel::new(Arc::new(ikigai_fs::cacheable_space(root)));
    let read = || request(Verb::Source, "listing");
    assert_eq!(block_on(current.issue(read(), &cap)).unwrap().bytes, b"a");
    assert!(!current.is_cached(&read(), &cap));
    // A distinct OS process, with no kernel or watcher involvement.
    assert!(std::process::Command::new("python3")
        .arg("-c")
        .arg("import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('b')")
        .arg(dir.join("b"))
        .status()
        .unwrap()
        .success());
    assert_eq!(
        block_on(current.issue(read(), &cap)).unwrap().bytes,
        b"a\nb"
    );
    println!("PASS current: external create visible; unchanged listing is NOT cached");

    // Deliberately unsafe spike: change only the listing's cache flag.
    let ep = Arc::new(FileEndpoint::new(root));
    let invocations = Arc::new(AtomicUsize::new(0));
    let invocation_count = invocations.clone();
    let naive = AsyncFnEndpoint::new("unsafe-listing-cache", move |inv| {
        let ep = ep.clone();
        invocation_count.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            let mut repr = ep.invoke(inv).await?;
            if inv.request.verb == Verb::Source {
                repr = repr.cacheable();
            }
            Ok(repr)
        })
    });
    let kernel = Kernel::new(Arc::new(
        EndpointSpace::new().bind(UriTemplate::parse("urn:file:{path}").unwrap(), naive),
    ));
    assert_eq!(block_on(kernel.issue(read(), &cap)).unwrap().bytes, b"a\nb");
    assert!(kernel.is_cached(&read(), &cap));
    assert_eq!(block_on(kernel.issue(read(), &cap)).unwrap().bytes, b"a\nb");
    assert_eq!(invocations.load(Ordering::Relaxed), 1);
    fs::write(dir.join("c"), b"c").unwrap();
    kernel.cut("urn:file:listing/c");
    assert_eq!(block_on(kernel.issue(read(), &cap)).unwrap().bytes, b"a\nb");
    println!("PASS unsafe spike reproduces stale set after child-only cut");
    assert_eq!(invocations.load(Ordering::Relaxed), 1);
    kernel.cut("urn:file:listing");
    assert_eq!(
        block_on(kernel.issue(read(), &cap)).unwrap().bytes,
        b"a\nb\nc"
    );
    println!("PASS parent cut repairs it after delivery; says nothing about delivery latency");
    assert_eq!(invocations.load(Ordering::Relaxed), 2);

    let sink = request(Verb::Sink, "listing/d").with_arg("content", ArgRef::Inline(b"d".to_vec()));
    block_on(kernel.issue(sink, &cap)).unwrap();
    assert_eq!(
        block_on(kernel.issue(read(), &cap)).unwrap().bytes,
        b"a\nb\nc"
    );
    println!("PASS unsafe spike also stays stale after a real kernel Sink creates a child");

    // The unchanged endpoint still sees a real Sink's newly created child.
    let fixed = Kernel::new(Arc::new(ikigai_fs::cacheable_space(root)));
    let sink = request(Verb::Sink, "listing/e").with_arg("content", ArgRef::Inline(b"e".to_vec()));
    block_on(fixed.issue(sink, &cap)).unwrap();
    assert_eq!(
        block_on(fixed.issue(read(), &cap)).unwrap().bytes,
        b"a\nb\nc\nd\ne"
    );
}

fn fanout() {
    for n in [1, 100, 1_000] {
        let mut samples = Vec::new();
        for _ in 0..31 {
            let endpoint = FnEndpoint::new("dependent", |_| {
                Ok(
                    Representation::new(ReprType::new("text/plain"), b"x".to_vec())
                        .cacheable()
                        .depends_on("urn:file:listing"),
                )
            });
            let kernel = Kernel::new(Arc::new(
                EndpointSpace::new()
                    .bind(UriTemplate::parse("urn:dependent:{id}").unwrap(), endpoint),
            ));
            for i in 0..n {
                block_on(kernel.issue(
                    Request::new(
                        Verb::Source,
                        Iri::parse(format!("urn:dependent:{i}")).unwrap(),
                    ),
                    &Capability::root(),
                ))
                .unwrap();
            }
            let start = Instant::now();
            kernel.cut("urn:file:listing");
            samples.push(start.elapsed().as_nanos());
        }
        samples.sort_unstable();
        println!(
            "cut-populated,{n},31,{},{},{}",
            samples[0], samples[15], samples[28]
        );
    }
}

fn events(root: &Path) {
    fs::create_dir_all(root.join("a")).unwrap();
    fs::create_dir_all(root.join("b")).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |e| {
        tx.send((Instant::now(), e)).unwrap();
    })
    .unwrap();
    watcher.watch(root, RecursiveMode::Recursive).unwrap();
    let drain = |phase: &str, start: Instant| {
        let deadline = Instant::now() + Duration::from_millis(200);
        let mut count = 0;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(left) {
                Ok((received, event)) => {
                    count += 1;
                    println!(
                        "{phase}: callback_after_us={} {event:?}",
                        received.duration_since(start).as_micros()
                    );
                }
                Err(_) => break,
            }
        }
        count
    };
    drain("startup", Instant::now());
    let start = Instant::now();
    fs::write(root.join("a/x"), b"x").unwrap();
    drain("create", start);
    let start = Instant::now();
    fs::rename(root.join("a/x"), root.join("b/y")).unwrap();
    drain("cross-directory-rename", start);
    let start = Instant::now();
    fs::write(root.join("b/y"), b"changed in place").unwrap();
    drain("in-place", start);
    let start = Instant::now();
    fs::remove_file(root.join("b/y")).unwrap();
    drain("remove", start);
}

fn churn(root: &Path) {
    use notify::{event::ModifyKind, EventKind};
    println!("entries,operations,write_ns,no_watch_ns,events,structural_events,content_events");
    for n in [10, 1_000, 100_000] {
        let dir = root.join(n.to_string());
        fs::create_dir_all(&dir).unwrap();
        for i in 0..n {
            fs::write(dir.join(format!("file-{i:06}")), b"x").unwrap();
        }
        let start = Instant::now();
        for i in 0..1_000 {
            fs::write(dir.join(format!("file-{:06}", i % n)), b"y").unwrap();
        }
        let no_watch = start.elapsed().as_nanos();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |e| {
            let _ = tx.send(e);
        })
        .unwrap();
        watcher.watch(&dir, RecursiveMode::NonRecursive).unwrap();
        let start = Instant::now();
        for i in 0..1_000 {
            fs::write(dir.join(format!("file-{:06}", i % n)), b"z").unwrap();
        }
        let write = start.elapsed().as_nanos();
        let mut total = 0;
        let mut structural = 0;
        let mut content = 0;
        while let Ok(event) = rx.recv_timeout(Duration::from_millis(200)) {
            let event = event.unwrap();
            total += 1;
            match event.kind {
                EventKind::Create(_)
                | EventKind::Remove(_)
                | EventKind::Modify(ModifyKind::Name(_)) => structural += 1,
                EventKind::Modify(ModifyKind::Data(_)) => content += 1,
                _ => (),
            }
        }
        println!("{n},1000,{write},{no_watch},{total},{structural},{content}");
    }
}

fn revalidation(root: &Path) {
    use std::os::unix::fs::MetadataExt;
    fs::create_dir_all(root.join("listing")).unwrap();
    fs::write(root.join("listing/a"), b"a").unwrap();
    for mode in ["stat", "hash"] {
        let ep = Arc::new(FileEndpoint::new(root));
        let path = root.join("listing");
        let scans = Arc::new(AtomicUsize::new(0));
        let produced = Arc::new(AtomicUsize::new(0));
        let composites = Arc::new(AtomicUsize::new(0));
        let scan_count = scans.clone();
        let produce_count = produced.clone();
        let origin = AsyncFnEndpoint::new("conditional-listing", move |inv| {
            let ep = ep.clone();
            let path = path.clone();
            let scans = scan_count.clone();
            let produced = produce_count.clone();
            Box::pin(async move {
                let now = inv.now().unwrap();
                let stamp = || {
                    let m = fs::metadata(&path).unwrap();
                    format!(
                        "{}:{}:{}:{}:{}",
                        m.dev(),
                        m.ino(),
                        m.mtime(),
                        m.mtime_nsec(),
                        m.size()
                    )
                };
                let mut repr = None;
                let tag = if mode == "stat" {
                    stamp()
                } else {
                    scans.fetch_add(1, Ordering::Relaxed);
                    let answer = ep.invoke(inv).await?;
                    let tag = ContentId::of(&answer.bytes).to_string();
                    repr = Some(answer);
                    tag
                };
                if inv.stale().and_then(|s| s.validator.etag.as_ref()) == Some(&tag) {
                    return Ok(Representation::revalidated(now));
                }
                let answer = match repr {
                    Some(answer) => answer,
                    None => {
                        scans.fetch_add(1, Ordering::Relaxed);
                        ep.invoke(inv).await?
                    }
                };
                produced.fetch_add(1, Ordering::Relaxed);
                Ok(answer.cacheable_until(now).validated_by(OriginValidator {
                    etag: Some(tag),
                    last_modified: None,
                }))
            })
        });
        let count = composites.clone();
        let composite = AsyncFnEndpoint::new("composite", move |inv| {
            let count = count.clone();
            Box::pin(async move {
                count.fetch_add(1, Ordering::Relaxed);
                let bytes = inv
                    .source(&Iri::parse("urn:file:listing").unwrap())
                    .await?
                    .bytes;
                Ok(Representation::new(ReprType::new("text/plain"), bytes).cacheable())
            })
        });
        let kernel = Kernel::new(Arc::new(
            EndpointSpace::new()
                .bind(UriTemplate::parse("urn:file:{path}").unwrap(), origin)
                .bind(Exact::new("urn:composite"), composite),
        ))
        .with_clock(Arc::new(FixedClock::at(1_000)));
        let read = || Request::new(Verb::Source, Iri::parse("urn:composite").unwrap());
        let cap = Capability::root();
        for _ in 0..2 {
            assert_eq!(block_on(kernel.issue(read(), &cap)).unwrap().bytes, b"a");
        }
        assert_eq!(produced.load(Ordering::Relaxed), 1);
        assert_eq!(composites.load(Ordering::Relaxed), 2);
        assert_eq!(
            scans.load(Ordering::Relaxed),
            if mode == "stat" { 1 } else { 2 }
        );
        println!(
            "{mode}: unchanged reads=2 scans={} produced={} composite_runs={}",
            scans.load(Ordering::Relaxed),
            produced.load(Ordering::Relaxed),
            composites.load(Ordering::Relaxed)
        );
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .expect("bench | reproduce | fanout | events | churn | revalidation");
    if mode == "fanout" {
        fanout();
        return;
    }
    let root = std::path::PathBuf::from(args.next().expect("scratch path inside this checkout"));
    assert!(!root.exists(), "use a fresh scratch directory");
    fs::create_dir_all(&root).unwrap();
    match mode.as_str() {
        "bench" => bench(&root),
        "reproduce" => reproduce(&root),
        "events" => events(&root),
        "revalidation" => revalidation(&root),
        "churn" => churn(&root),
        _ => panic!("unknown mode"),
    }
    fs::remove_dir_all(root).unwrap();
}

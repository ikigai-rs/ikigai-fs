//! **A directory's listing** (ledger #2524): `source urn:file:<dir>` answers the newline
//! list of the directory's child names, so a folder of files is a set resource a map (`..`)
//! walks, and a file added to it is in the next listing with no edit to whatever maps it.
//! The jail's rules hold for the listing as for a read: a link is never listed nor followed,
//! a name the jail would refuse to serve is not listed, and a child the capability does not
//! grant `read` on is not named.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use futures::executor::block_on;
use ikigai_core::{
    ArgRef, Bindings, Capability, Endpoint, Error, Invocation, Iri, Kernel, ReprType, Request, Verb,
};
use ikigai_fs::FileEndpoint;

struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "ikigai-fs-listing-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        Root(dir)
    }

    fn write(&self, rel: &str, bytes: &[u8]) {
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn source(
    endpoint: &FileEndpoint,
    rel: &str,
    cap: &Capability,
) -> Result<(ReprType, String), Error> {
    source_face(endpoint, rel, cap, None)
}

fn source_face(
    endpoint: &FileEndpoint,
    rel: &str,
    cap: &Capability,
    face: Option<&str>,
) -> Result<(ReprType, String), Error> {
    let mut request = Request::new(Verb::Source, Iri::parse(format!("urn:file:{rel}")).unwrap());
    if let Some(face) = face {
        request = request.with_arg("as", ArgRef::Inline(face.as_bytes().to_vec()));
    }
    let mut bindings = Bindings::new();
    bindings.insert("path", rel);
    let inv = Invocation::detached(&request, &bindings, cap);
    let buffered = block_on(endpoint.invoke(&inv))?;
    // The body path answers the same listing.
    let body = block_on(endpoint.invoke_body(&inv))?;
    assert_eq!(body.repr_type, buffered.repr_type);
    let collected = block_on(body.collect(usize::MAX))?;
    assert_eq!(collected.bytes, buffered.bytes);
    Ok((
        buffered.repr_type,
        String::from_utf8(buffered.bytes).unwrap(),
    ))
}

fn listing(endpoint: &FileEndpoint, rel: &str) -> String {
    source(endpoint, rel, &Capability::root()).unwrap().1
}

#[test]
fn a_directory_sources_as_the_newline_list_of_its_child_names() {
    let root = Root::new("names");
    root.write("searches/caching.rq", b"SELECT 1");
    root.write("searches/actors.rq", b"SELECT 2");
    root.write("searches/nested/deep.rq", b"SELECT 3");
    let endpoint = FileEndpoint::new(&root.0);
    let (repr_type, text) = source(&endpoint, "searches", &Capability::root()).unwrap();
    assert_eq!(
        repr_type,
        ReprType::new("text/plain").with_param("charset", "utf-8")
    );
    // Sorted, one name per line, no trailing newline (a map splits on `\n`, so a trailing
    // one would be an empty item). A subdirectory is a child too: its listing is a resource.
    assert_eq!(text, "actors.rq\ncaching.rq\nnested");
    assert_eq!(listing(&endpoint, "searches/nested"), "deep.rq");
}

#[test]
fn an_empty_directory_lists_nothing() {
    let root = Root::new("empty");
    std::fs::create_dir(root.0.join("searches")).unwrap();
    let ep = FileEndpoint::new(&root.0);
    assert_eq!(listing(&ep, "searches"), "");
    assert_eq!(
        source_face(&ep, "searches", &Capability::root(), Some("text/uri-list"))
            .unwrap()
            .1,
        ""
    );
}

#[test]
fn a_file_added_or_removed_is_in_the_next_listing_even_on_a_cacheable_mount() {
    let root = Root::new("live");
    root.write("searches/a.rq", b"a");
    let space = ikigai_fs::cacheable_space(&root.0);
    let kernel = Kernel::new(Arc::new(space));
    let cap = Capability::root();
    let list = || {
        let request = Request::new(Verb::Source, Iri::parse("urn:file:searches").unwrap());
        String::from_utf8(block_on(kernel.issue(request, &cap)).unwrap().bytes).unwrap()
    };
    assert_eq!(list(), "a.rq");
    // Added out of band (no watcher here): the next listing names it.
    root.write("searches/b.rq", b"b");
    assert_eq!(list(), "a.rq\nb.rq");
    // Added through the kernel: its Sink cuts only `urn:file:searches/c.rq`.
    let sink = Request::new(Verb::Sink, Iri::parse("urn:file:searches/c.rq").unwrap())
        .with_arg("content", ArgRef::Inline(b"c".to_vec()));
    block_on(kernel.issue(sink, &cap)).unwrap();
    assert_eq!(list(), "a.rq\nb.rq\nc.rq");
    std::fs::remove_file(root.0.join("searches/a.rq")).unwrap();
    assert_eq!(list(), "b.rq\nc.rq");
}

#[test]
fn links_and_names_the_jail_refuses_are_not_listed() {
    let root = Root::new("jail");
    let outside = Root::new("outside");
    outside.write("secret.txt", b"secret");
    root.write("searches/kept.rq", b"kept");
    let dir = root.0.join("searches");
    std::os::unix::fs::symlink(outside.0.join("secret.txt"), dir.join("leaf-link")).unwrap();
    std::os::unix::fs::symlink(&outside.0, dir.join("dir-link")).unwrap();
    // Each a legal name on Unix that the jail refuses to serve.
    for name in ["CON", "aux.c", "trailing.", "a:b", "back\\slash"] {
        std::fs::write(dir.join(name), b"x").unwrap();
    }
    // A Sink's staging name (one a killed process can leave behind) is not a file of the set.
    std::fs::write(
        dir.join(".ikigai-fs-0123456789abcdef0123456789abcdef.tmp"),
        b"x",
    )
    .unwrap();
    assert_eq!(listing(&FileEndpoint::new(&root.0), "searches"), "kept.rq");
    assert_eq!(
        source_face(
            &FileEndpoint::new(&root.0),
            "searches",
            &Capability::root(),
            Some("text/uri-list")
        )
        .unwrap()
        .1,
        "urn:file:searches/kept.rq"
    );
}

#[test]
fn a_linked_or_misspelled_directory_is_refused_as_a_read_is() {
    let root = Root::new("refused");
    let outside = Root::new("refused-outside");
    outside.write("x.rq", b"x");
    std::os::unix::fs::symlink(&outside.0, root.0.join("linked")).unwrap();
    root.write("searches/a.rq", b"a");
    let endpoint = FileEndpoint::new(&root.0);
    let all = Capability::root();
    for rel in ["linked", "searches/", "./searches", "searches//", "../x"] {
        let err = source(&endpoint, rel, &all).unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument { .. }),
            "{rel}: {err:?}"
        );
    }
    assert!(matches!(
        source(&endpoint, "missing", &all),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn the_listing_is_a_read_of_the_directory_and_names_only_children_the_capability_grants() {
    let root = Root::new("acl");
    root.write("searches/public.rq", b"p");
    root.write("searches/secret.rq", b"s");
    root.write("searches/hidden/x.rq", b"x");
    let endpoint = FileEndpoint::new(&root.0);
    let base = root.0.display().to_string();
    let read = |path: &str| format!("urn:cap:fs:read:{path}");
    let granted = Capability::scoped([
        read(&format!("{base}/searches")),
        read(&format!("-{base}/searches/secret.rq")),
        read(&format!("-{base}/searches/hidden")),
    ]);
    assert_eq!(
        source(&endpoint, "searches", &granted).unwrap().1,
        "public.rq"
    );
    // A read granted only on a child is no grant on the directory's listing.
    let child_only = Capability::scoped([read(&format!("{base}/searches/public.rq"))]);
    assert!(matches!(
        source(&endpoint, "searches", &child_only),
        Err(Error::Denied(_))
    ));
    // A write grant is no read.
    let write_only = Capability::scoped([format!("urn:cap:fs:write:{base}")]);
    assert!(matches!(
        source(&endpoint, "searches", &write_only),
        Err(Error::Denied(_))
    ));
}

#[test]
fn a_directory_still_is_not_a_file_to_delete_or_sink() {
    let root = Root::new("verbs");
    root.write("searches/a.rq", b"a");
    let endpoint = FileEndpoint::new(&root.0);
    let all = Capability::root();
    for (verb, args) in [
        (Verb::Delete, vec![]),
        (Verb::Sink, vec![("content", b"x".as_slice())]),
    ] {
        let mut request = Request::new(verb, Iri::parse("urn:file:searches").unwrap());
        for (name, value) in &args {
            request = request.with_arg(*name, ArgRef::Inline(value.to_vec()));
        }
        let mut bindings = Bindings::new();
        bindings.insert("path", "searches");
        let inv = Invocation::detached(&request, &bindings, &all);
        let err = block_on(endpoint.invoke(&inv)).unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument { .. }),
            "{verb:?}: {err:?}"
        );
    }
    assert!(Path::new(&root.0.join("searches/a.rq")).is_file());
}

fn saved_search_engine(root: &Root) -> ikigai_engine::Engine {
    let space = ikigai_sparql::space()
        .bind(
            ikigai_core::Exact::new("urn:iki:fn:compose"),
            ikigai_fn::compose(),
        )
        .bind(
            ikigai_core::UriTemplate::parse(ikigai_fs::FILE_TEMPLATE).unwrap(),
            FileEndpoint::new(&root.0),
        );
    ikigai_engine::Engine::new(Arc::new(Kernel::with_meta_renderer(
        Arc::new(space),
        Arc::new(JsonRenderer),
    )))
}

fn output(engine: &ikigai_engine::Engine, line: &str) -> Result<String, String> {
    match engine.eval(line) {
        ikigai_engine::Action::Output(entry) => entry.result,
        _ => panic!("expected output"),
    }
}

#[test]
fn a_uri_listing_map_runs_both_saved_searches() {
    let root = Root::new("saved-searches");
    root.write("searches/caching.rq", b"SELECT (1 AS ?answer) WHERE {}");
    root.write("searches/rss.rq", b"SELECT (2 AS ?answer) WHERE {}");
    let engine = saved_search_engine(&root);
    let bare = output(
        &engine,
        "source urn:file:searches .. ( urn:iki:fn:compose | urn:sparql:select as=text/csv )",
    )
    .unwrap_err();
    assert!(bare.contains("not an IRI"), "{bare}");
    let answer = output(
        &engine,
        "source urn:file:searches as=text/uri-list .. ( urn:iki:fn:compose | urn:sparql:select as=text/csv )",
    ).unwrap();
    assert_eq!(answer.replace("\r\n", "\n"), "answer\n1\n\nanswer\n2\n");
    assert_eq!(engine.last_fan_out().unwrap().nominal, 2);
}

struct JsonRenderer;
impl ikigai_core::MetaRenderer for JsonRenderer {
    fn render(
        &self,
        description: &ikigai_core::Description,
        _: &ReprType,
    ) -> ikigai_core::Result<ikigai_core::Representation> {
        Ok(ikigai_core::Representation::new(
            ReprType::new("application/json"),
            serde_json::to_vec(description).unwrap(),
        ))
    }
}

#[test]
fn uri_members_encode_each_utf8_path_and_round_trip_through_the_kernel() {
    let root = Root::new("escaped");
    for name in [
        "two words.rq",
        "café.rq",
        "100%.rq",
        "hash#query?.rq",
        "line\nbreak.rq",
    ] {
        root.write(&format!("saved searches/{name}"), name.as_bytes());
    }
    root.write("saved searches/nested/file.rq", b"nested");
    let ep = FileEndpoint::new(&root.0);
    let (repr, text) = source_face(
        &ep,
        "saved%20searches",
        &Capability::root(),
        Some("text/uri-list"),
    )
    .unwrap();
    assert_eq!(repr, ReprType::new("text/uri-list"));
    assert_eq!(
        text,
        [
            "urn:file:saved%20searches/100%25.rq",
            "urn:file:saved%20searches/caf%C3%A9.rq",
            "urn:file:saved%20searches/hash%23query%3F.rq",
            "urn:file:saved%20searches/line%0Abreak.rq",
            "urn:file:saved%20searches/nested",
            "urn:file:saved%20searches/two%20words.rq",
        ]
        .join("\n")
    );
    let kernel = Kernel::new(Arc::new(ikigai_fs::space(&root.0)));
    for uri in text.lines() {
        let answer = block_on(kernel.issue(
            Request::new(Verb::Source, Iri::parse(uri).unwrap()),
            &Capability::root(),
        ))
        .unwrap();
        assert!(!answer.bytes.is_empty(), "{uri}");
    }
    assert_eq!(
        listing(&ep, "saved%20searches"),
        "100%.rq\ncafé.rq\nhash#query?.rq\nline\nbreak.rq\nnested\ntwo words.rq"
    );
    assert_eq!(
        source_face(
            &ep,
            "saved%20searches",
            &Capability::root(),
            Some("application/octet-stream")
        )
        .unwrap()
        .1,
        listing(&ep, "saved%20searches")
    );
}

#[test]
fn uri_face_is_directory_only_and_declared_on_the_source_contract() {
    let root = Root::new("uri-contract");
    root.write("file.rq", b"SELECT 1");
    let ep = FileEndpoint::new(&root.0);
    assert!(
        matches!(source_face(&ep, "file.rq", &Capability::root(), Some("text/uri-list")), Err(Error::InvalidArgument { name, .. }) if name == "as")
    );
    let description = ep.describe();
    description.validate().unwrap();
    let action = description
        .action_specs()
        .into_iter()
        .find(|a| a.verb == Verb::Source)
        .unwrap();
    let as_arg = action.inputs.iter().find(|a| a.name == "as").unwrap();
    assert!(as_arg.one_of.contains(&"text/uri-list".to_string()));
    assert!(action.outputs.iter().any(|o| o == "text/uri-list"));
}

#[test]
fn encoded_paths_cannot_bypass_canonical_spelling_or_the_acl() {
    let root = Root::new("encoded-jail");
    root.write("searches/two words.rq", b"private");
    let ep = FileEndpoint::new(&root.0);
    let cap = Capability::scoped([
        format!("urn:cap:fs:read:{}", root.0.display()),
        format!(
            "urn:cap:fs:read:-{}/searches/two words.rq",
            root.0.display()
        ),
    ]);
    assert_eq!(
        source_face(&ep, "searches", &cap, Some("text/uri-list"))
            .unwrap()
            .1,
        ""
    );
    assert!(matches!(
        source(&ep, "searches/two%20words.rq", &cap),
        Err(Error::Denied(_))
    ));
    for path in [
        "searches%2Ftwo%20words.rq",
        "searches/%2E%2E/secret",
        "searches/two%20words%2erq",
        "searches/%FF",
        "searches/%00",
    ] {
        assert!(
            matches!(
                source(&ep, path, &Capability::root()),
                Err(Error::InvalidArgument { .. })
            ),
            "{path}"
        );
    }
}

#[test]
fn uri_listings_stay_live_and_encoded_file_writes_cut_their_cache_thread() {
    let root = Root::new("uri-cache");
    root.write("searches/two words.rq", b"old");
    let kernel = Kernel::new(Arc::new(ikigai_fs::cacheable_space(&root.0)));
    let cap = Capability::root();
    let read = |uri: &str, face: Option<&str>| {
        let mut request = Request::new(Verb::Source, Iri::parse(uri).unwrap());
        if let Some(face) = face {
            request = request.with_arg("as", ArgRef::Inline(face.as_bytes().to_vec()));
        }
        block_on(kernel.issue(request, &cap)).unwrap().bytes
    };
    let uri = "urn:file:searches/two%20words.rq";
    assert_eq!(read(uri, None), b"old");
    root.write("searches/two words.rq", b"external");
    assert!(
        matches!(
            block_on(kernel.issue(Request::new(Verb::Source, Iri::parse(uri).unwrap()), &cap)),
            Err(Error::Conflict(_))
        ),
        "cached bodies still refuse external changes"
    );
    let sink = Request::new(Verb::Sink, Iri::parse(uri).unwrap())
        .with_arg("content", ArgRef::Inline(b"new".to_vec()));
    block_on(kernel.issue(sink, &cap)).unwrap();
    assert_eq!(read(uri, None), b"new");
    assert_eq!(
        read("urn:file:searches", Some("text/uri-list")),
        uri.as_bytes()
    );
    root.write("searches/café.rq", b"added");
    assert_eq!(
        read("urn:file:searches", Some("text/uri-list")),
        b"urn:file:searches/caf%C3%A9.rq\nurn:file:searches/two%20words.rq"
    );
    let exists = Request::new(Verb::Exists, Iri::parse(uri).unwrap());
    assert_eq!(
        block_on(kernel.issue(exists.clone(), &cap)).unwrap().bytes,
        b"true"
    );
    block_on(kernel.issue(Request::new(Verb::Delete, Iri::parse(uri).unwrap()), &cap)).unwrap();
    assert_eq!(
        block_on(kernel.issue(exists, &cap)).unwrap().bytes,
        b"false"
    );
    assert_eq!(
        read("urn:file:searches", Some("text/uri-list")),
        b"urn:file:searches/caf%C3%A9.rq"
    );
}

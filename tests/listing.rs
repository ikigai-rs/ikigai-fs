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
    let request = Request::new(Verb::Source, Iri::parse(format!("urn:file:{rel}")).unwrap());
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
    assert_eq!(listing(&FileEndpoint::new(&root.0), "searches"), "");
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

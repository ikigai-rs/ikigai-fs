//! Regression for #2532: serve extension types on both the buffered and body paths.
#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;

use futures::executor::block_on;
use ikigai_core::{
    ArgRef, Bindings, Capability, Endpoint, Exact, Invocation, Iri, Kernel, ReprType, Request, Verb,
};
use ikigai_fs::FileEndpoint;

struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("media-types-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn files_are_served_with_specific_extension_types() {
    let root = Root::new("extensions");
    let endpoint = FileEndpoint::new(&root.0);
    let mut failures = Vec::new();
    for (ext, expected) in [
        ("txt", "text/plain"),
        ("md", "text/markdown"),
        ("ttl", "text/turtle"),
        ("nt", "application/n-triples"),
        ("json", "application/json"),
        ("jsonld", "application/ld+json"),
        ("html", "text/html"),
        ("arrangement", "text/x-ikigai-arrangement"),
        ("geojson", "application/geo+json"),
        ("xml", "text/xml"),
        ("rss", "application/rss+xml"),
        ("opml", "text/x-opml"),
        ("rdf", "application/rdf+xml"),
        ("xsl", "text/xml"),
        ("rq", "application/sparql-query"),
        ("svg", "image/svg+xml"),
        ("csv", "text/csv"),
    ] {
        let name = format!("file.{ext}");
        std::fs::write(root.0.join(&name), b"fixture").unwrap();
        let request = Request::new(
            Verb::Source,
            Iri::parse(format!("urn:file:{name}")).unwrap(),
        );
        let mut bindings = Bindings::new();
        bindings.insert("path", name.as_str());
        let cap = Capability::root();
        let inv = Invocation::detached(&request, &bindings, &cap);
        let buffered = block_on(endpoint.invoke(&inv)).unwrap();
        let body = block_on(endpoint.invoke_body(&inv)).unwrap();
        for (path, actual) in [("buffered", buffered.repr_type), ("body", body.repr_type)] {
            // Known extensions have no charset parameter today, including text types.
            if actual != ReprType::new(expected) {
                failures.push(format!("{name} ({path}): {actual:?}, expected {expected}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn unknown_and_missing_extensions_keep_utf8_and_binary_fallbacks() {
    let root = Root::new("fallbacks");
    let endpoint = FileEndpoint::new(&root.0);
    for name in ["no-extension", "file.unknown2532"] {
        for bytes in [b"hello".as_slice(), &[0xff, 0xfe]] {
            std::fs::write(root.0.join(name), bytes).unwrap();
            let request = Request::new(
                Verb::Source,
                Iri::parse(format!("urn:file:{name}")).unwrap(),
            );
            let mut bindings = Bindings::new();
            bindings.insert("path", name);
            let cap = Capability::root();
            let inv = Invocation::detached(&request, &bindings, &cap);
            let expected = if bytes == b"hello" {
                ReprType::new("text/plain").with_param("charset", "utf-8")
            } else {
                ReprType::new("application/octet-stream")
            };
            assert_eq!(block_on(endpoint.invoke(&inv)).unwrap().repr_type, expected);
            assert_eq!(
                block_on(endpoint.invoke_body(&inv)).unwrap().repr_type,
                expected
            );
        }
    }
}

#[test]
fn geojson_queries_answer_through_the_kernel_like_json() {
    let root = Root::new("query");
    let features = vec!["{}"; 178].join(",");
    let content = format!(r#"{{"type":"FeatureCollection","features":[{features}]}}"#);
    let space = ikigai_fs::space(&root.0).bind(Exact::new("urn:json:query"), ikigai_json::query());
    let kernel = Kernel::new(Arc::new(space));
    for ext in ["json", "geojson"] {
        let name = format!("quakes-2024-01-01.{ext}");
        std::fs::write(root.0.join(&name), &content).unwrap();
        let request = Request::new(Verb::Source, Iri::parse("urn:json:query").unwrap())
            .with_arg(
                "src",
                ArgRef::Inline(format!("urn:file:{name}").into_bytes()),
            )
            .with_arg("q", ArgRef::Inline(b".features|length".to_vec()));
        let answer = block_on(kernel.issue(request, &Capability::root())).unwrap();
        assert_eq!(answer.bytes, b"178", "{ext}");
    }
}

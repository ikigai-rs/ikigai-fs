//! The same Sink contract exercised on disk and in a real browser's localStorage.
#![cfg(any(unix, target_family = "wasm"))]

use futures::executor::block_on;
use ikigai_core::{ArgRef, Bindings, Capability, Endpoint, Error, Invocation, Iri, Request, Verb};
use ikigai_fs::FileEndpoint;
use std::path::PathBuf;

#[cfg(target_family = "wasm")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        #[cfg(unix)]
        let root =
            std::env::temp_dir().join(format!("ikigai-fs-encoding-{}-{name}", std::process::id()));
        #[cfg(target_family = "wasm")]
        let root = PathBuf::from(format!("encoding-tests/{name}"));
        #[cfg(unix)]
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn sink(
        &self,
        content: &[u8],
        encoding: Option<&[u8]>,
    ) -> ikigai_core::Result<ikigai_core::Representation> {
        let mut req = Request::new(Verb::Sink, Iri::parse("urn:file:data.bin").unwrap())
            .with_arg("content", ArgRef::Inline(content.to_vec()));
        if let Some(encoding) = encoding {
            req = req.with_arg("encoding", ArgRef::Inline(encoding.to_vec()));
        }
        let mut bindings = Bindings::new();
        bindings.insert("path", "data.bin");
        block_on(FileEndpoint::new(&self.0).invoke(&Invocation::detached(
            &req,
            &bindings,
            &Capability::root(),
        )))
    }

    fn bytes(&self) -> Vec<u8> {
        #[cfg(unix)]
        {
            std::fs::read(self.0.join("data.bin")).unwrap()
        }
        #[cfg(target_family = "wasm")]
        {
            let req = Request::new(Verb::Source, Iri::parse("urn:file:data.bin").unwrap())
                .with_arg("as", ArgRef::Inline(b"application/octet-stream".to_vec()));
            let mut bindings = Bindings::new();
            bindings.insert("path", "data.bin");
            block_on(FileEndpoint::new(&self.0).invoke(&Invocation::detached(
                &req,
                &bindings,
                &Capability::root(),
            )))
            .unwrap()
            .bytes
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        #[cfg(unix)]
        std::fs::remove_dir_all(&self.0).unwrap();
        #[cfg(target_family = "wasm")]
        {
            let storage = web_sys::window().unwrap().local_storage().unwrap().unwrap();
            for prefix in ["ikigai:fs:", "ikigai:fs-bytes:"] {
                storage
                    .remove_item(&format!("{prefix}{}/data.bin", self.0.display()))
                    .unwrap();
            }
        }
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_family = "wasm"), test)]
fn base64_writes_exact_binary_bytes() {
    let f = Fixture::new("binary");
    let ack = f.sink(b"AP/+gA==", Some(b"base64")).unwrap();
    assert_eq!(f.bytes(), [0, 255, 254, 128]);
    assert!(String::from_utf8(ack.bytes)
        .unwrap()
        .starts_with("wrote 4 bytes"));
}

#[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_family = "wasm"), test)]
fn malformed_base64_is_invalid_argument_and_preserves_file() {
    let f = Fixture::new("malformed");
    f.sink(b"original", None).unwrap();
    for bad in [
        b"%%%".as_slice(),
        b"Zg",
        b"Zh==",
        b"Zg==\n",
        b"_w==",
        b"\xff",
    ] {
        assert!(
            matches!(f.sink(bad, Some(b"base64")), Err(Error::InvalidArgument { name, .. }) if name == "content")
        );
        assert_eq!(f.bytes(), b"original");
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_family = "wasm"), test)]
fn default_and_explicit_utf8_refuse_non_utf8() {
    let f = Fixture::new("utf8");
    f.sink(b"original", None).unwrap();
    for encoding in [None, Some(b"utf-8".as_slice())] {
        assert!(
            matches!(f.sink(&[0, 255, 254, 128], encoding), Err(Error::InvalidArgument { name, .. }) if name == "content")
        );
        assert_eq!(f.bytes(), b"original");
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_family = "wasm"), test)]
fn utf8_empty_and_invalid_encoding() {
    let f = Fixture::new("text");
    for encoding in [None, Some(b"utf-8".as_slice())] {
        f.sink("hello \u{1f30d}\0".as_bytes(), encoding).unwrap();
        assert_eq!(f.bytes(), "hello \u{1f30d}\0".as_bytes());
    }
    for encoding in [b"base64".as_slice(), b"utf-8"] {
        f.sink(b"", Some(encoding)).unwrap();
        assert!(f.bytes().is_empty());
    }
    for encoding in [b"BASE64".as_slice(), b"", b"latin-1", b"\xff"] {
        assert!(
            matches!(f.sink(b"x", Some(encoding)), Err(Error::InvalidArgument { name, .. }) if name == "encoding")
        );
        assert!(f.bytes().is_empty());
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen_test::wasm_bindgen_test]
fn legacy_text_survives_then_can_be_overwritten_and_deleted() {
    let f = Fixture::new("legacy");
    let store = web_sys::window().unwrap().local_storage().unwrap().unwrap();
    let key = format!("ikigai:fs:{}/data.bin", f.0.display());
    // No marker-like legacy text can be mistaken for a binary envelope.
    let legacy = "\0ikigai-fs:base64:AP/+gA==";
    store.set_item(&key, legacy).unwrap();
    assert_eq!(f.bytes(), legacy.as_bytes());
    f.sink(b"AP/+gA==", Some(b"base64")).unwrap();
    assert_eq!(f.bytes(), [0, 255, 254, 128]);
    assert_eq!(
        store
            .get_item(&format!("ikigai:fs-bytes:{}/data.bin", f.0.display()))
            .unwrap()
            .unwrap(),
        "AP/+gA=="
    );
    let req = Request::new(Verb::Delete, Iri::parse("urn:file:data.bin").unwrap());
    let mut bindings = Bindings::new();
    bindings.insert("path", "data.bin");
    block_on(FileEndpoint::new(&f.0).invoke(&Invocation::detached(
        &req,
        &bindings,
        &Capability::root(),
    )))
    .unwrap();
    assert!(store.get_item(&key).unwrap().is_none());
    assert!(store
        .get_item(&format!("ikigai:fs-bytes:{}/data.bin", f.0.display()))
        .unwrap()
        .is_none());
}

#[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_family = "wasm"), test)]
fn encoding_is_declared_on_sink_and_aggregate_contracts() {
    let desc = FileEndpoint::new("unused").describe();
    let sink = desc
        .actions
        .iter()
        .find(|action| action.verb == Verb::Sink)
        .unwrap();
    for inputs in [&desc.inputs, &sink.inputs] {
        let encoding = inputs.iter().find(|arg| arg.name == "encoding").unwrap();
        assert!(!encoding.required);
        assert_eq!(encoding.default.as_deref(), Some("utf-8"));
        assert_eq!(encoding.one_of, ["utf-8", "base64"]);
        assert_eq!(
            encoding.class.as_deref(),
            Some("http://www.w3.org/2001/XMLSchema#string")
        );
        let content = inputs.iter().find(|arg| arg.name == "content").unwrap();
        assert_eq!(content.class, encoding.class);
    }
    assert!(
        sink.inputs
            .iter()
            .find(|arg| arg.name == "content")
            .unwrap()
            .required
    );
    assert!(desc
        .actions
        .iter()
        .filter(|action| action.verb != Verb::Sink)
        .all(|action| action.inputs.iter().all(|arg| arg.name != "encoding")));
}

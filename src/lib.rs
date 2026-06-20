//! `ikigai-fs` — a capability-gated file/store module.
//!
//! A standalone **ikigai module crate** (like `ikigai-fn` / `ikigai-personal`):
//! a host links it in and mounts [`space`], rather than the engine shipping file
//! behaviour itself. It depends only on the published `ikigai-core` kernel.
//!
//! Files are the most dangerous endpoint in the system — arbitrary filesystem
//! read *and* write — so access is confined by **two independent layers, both
//! required on every request**:
//!
//! 1. **The jail (structural, set at mount time).** [`FileEndpoint::new`] is
//!    handed a `root` directory and will never serve a path outside it: `..` and
//!    absolute segments are rejected, and an existing target's canonical path
//!    must still sit within the canonical root (symlink-safe). Fixed at mount —
//!    even a `root` capability cannot escape it.
//! 2. **The capability path-ACL (dynamic, per request).** The invocation's
//!    [`Capability`] must grant the request's action for the resolved path. A
//!    capability bug can never punch through the jail; the capability scopes
//!    *within* it.
//!
//! ## The capability path-ACL
//!
//! A file capability is carried as `urn:cap:` scopes of the form
//! `urn:cap:fs:<action>:<path>`, where `<action>` is `read` / `write` / `delete`
//! and `<path>` is an absolute directory or file. A leading `-` on the path
//! marks a **deny** (exclusion):
//!
//! - `urn:cap:fs:read:/Users/brian/workspace` — read anything under that dir.
//! - `urn:cap:fs:read:/Users/brian/workspace/public` (only) — an allowlist: read
//!   just that subtree, not the parent.
//! - `urn:cap:fs:read:/Users/brian/workspace` **+** `urn:cap:fs:read:-/Users/brian/workspace/secret`
//!   — read the tree *except* `secret`.
//!
//! Matching is **longest-prefix wins**, with **deny breaking ties**: for a
//! `(action, path)`, the most specific rule whose directory contains the path
//! decides; if the longest match is a deny, it's denied. No matching rule →
//! **default-deny**. A `root` capability allows everything *within the jail*.
//! These are owner-minted rule sets — the flat-scope [`Capability`] is untouched;
//! this module does the path-aware matching, where path semantics belong.
//!
//! ## Representations
//!
//! `Source` hands back a **string by default** (a known text media type from the
//! extension, or `text/plain` when the bytes decode as UTF-8); pass `as` =
//! `application/octet-stream` to get the raw **bytes** instead. `Sink` writes the
//! `content` argument's bytes. Reads are **uncacheable by default** — a file is a
//! live fact — but a mount can opt into caching them under a **golden thread**
//! ([`FileEndpoint::cacheable`] / [`cacheable_space`]): a `Sink`/`Delete` through
//! the kernel then invalidates the cached read (requires `ikigai-core` ≥ 0.1.9).
//!
//! ## Platforms
//!
//! One crate, a `cfg`-gated backend. The native backend stores in jailed
//! `std::fs`; the `wasm32` backend stores in the browser's `localStorage` (keyed
//! `ikigai:fs:<path>`), so the same module — same `file:` contract, same
//! capability scopes — links into a native CLI and an in-browser host alike. The
//! `localStorage` backend is text-oriented (it refuses non-UTF-8 writes).

use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use ikigai_core::{
    ArgSpec, Capability, Description, Endpoint, EndpointSpace, Error, Invocation, ReprType,
    Representation, Result, UriTemplate, Verb,
};

/// The conventional grammar a host mounts this module at: `urn:file:{path}`,
/// where `{path}` is captured root-relative and handed to the endpoint as the
/// `path` binding (so the file's *identity* is the request, not an argument).
pub const FILE_TEMPLATE: &str = "urn:file:{path}";

/// Mount the file module at its conventional grammar (`urn:file:{path}`), jailed
/// to `root`.
///
/// A host links this crate and mounts the returned space; the running principal's
/// [`Capability`] then scopes access *within* `root` via the path-ACL. Hosts that
/// want a different IRI grammar can bind [`FileEndpoint`] themselves.
pub fn space(root: impl Into<PathBuf>) -> EndpointSpace {
    EndpointSpace::new().bind(
        UriTemplate::parse(FILE_TEMPLATE).expect("FILE_TEMPLATE is a valid template"),
        FileEndpoint::new(root),
    )
}

/// Like [`space`], but **caches** `Source` reads under golden threads (see
/// [`FileEndpoint::cacheable`]). A `Sink`/`Delete` through the kernel invalidates
/// the cached read; suitable for a root written through ikigai. Requires a host
/// kernel that auto-cuts on writes (`ikigai-core` ≥ 0.1.9).
pub fn cacheable_space(root: impl Into<PathBuf>) -> EndpointSpace {
    EndpointSpace::new().bind(
        UriTemplate::parse(FILE_TEMPLATE).expect("FILE_TEMPLATE is a valid template"),
        FileEndpoint::new(root).cacheable(),
    )
}

/// A file endpoint jailed to a root directory, gated by the capability path-ACL.
pub struct FileEndpoint {
    root: PathBuf,
    cacheable: bool,
}

impl FileEndpoint {
    /// A file endpoint that will only ever serve paths within `root` (the jail).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        FileEndpoint {
            root: root.into(),
            cacheable: false,
        }
    }

    /// Cache `Source` reads under a golden thread (opt-in).
    ///
    /// By default a file is a *live fact* — every read recomputes — so a change
    /// made outside ikigai is always seen. Opt in to caching: each read is stored
    /// under the thread named after the resource (its `urn:file:` IRI), and a
    /// `Sink`/`Delete` through the kernel auto-cuts it, so writes invalidate
    /// correctly. **Caveat:** out-of-band changes (an editor, another process) are
    /// not seen until a kernel-mediated write — or an external watcher — cuts the
    /// thread. Enable only where that staleness window is acceptable (e.g. a root
    /// written through ikigai), until the watch policy lands.
    pub fn cacheable(mut self) -> Self {
        self.cacheable = true;
        self
    }

    /// Resolve a request-relative path to a real path within the root, or deny.
    /// This is the **jail** — structural confinement, consulted before the
    /// capability.
    fn resolve_within_root(&self, rel: &str) -> Result<PathBuf> {
        for component in Path::new(rel).components() {
            match component {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    return Err(deny("parent-directory (`..`) segments are not allowed"));
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(deny("absolute paths are not allowed"));
                }
            }
        }
        let target = self.root.join(rel);
        // Symlink-safe containment check when the target already exists.
        if let (Ok(canonical_root), Ok(canonical_target)) =
            (self.root.canonicalize(), target.canonicalize())
        {
            if !canonical_target.starts_with(&canonical_root) {
                return Err(Error::Endpoint(
                    "resolved path escapes the endpoint root".to_string(),
                ));
            }
        }
        Ok(target)
    }
}

#[async_trait]
impl Endpoint for FileEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let rel = inv
            .bindings
            .get("path")
            .ok_or_else(|| Error::MissingArgument("path".to_string()))?;

        // Layer 1 — the jail (structural). Even a root capability stops here.
        let target = self.resolve_within_root(rel)?;

        // Layer 2 — the capability path-ACL (dynamic). `Meta` never reaches an
        // endpoint (the kernel routes it through the meta renderer), so any verb
        // we see here is a content verb with a required action.
        let action = cap_action(inv.request.verb).ok_or_else(|| {
            Error::Endpoint(format!(
                "file endpoint does not support the {:?} verb",
                inv.request.verb
            ))
        })?;
        if !cap_allows(inv.capability, action, &target) {
            return Err(Error::Endpoint(format!(
                "capability does not grant `{action}` on `{rel}`"
            )));
        }

        match inv.request.verb {
            Verb::Source => {
                let bytes = backend_read(&target)?;
                let repr_type = source_type(&target, &bytes, inv.inline_str("as").ok());
                let repr = Representation::new(repr_type, bytes);
                if self.cacheable {
                    // Cache under a golden thread named after the resource. A
                    // `Sink`/`Delete` (kernel auto-cut) — or an external watcher —
                    // invalidates it. All representations of the file (string, raw
                    // bytes) share the thread, so one write invalidates them all.
                    Ok(repr.cacheable().depends_on(inv.request.target.as_str()))
                } else {
                    // Default: a file is a live fact, recomputed every read.
                    Ok(repr)
                }
            }
            Verb::Sink => {
                let content = inv.inline_arg("content")?;
                backend_write(&target, content)?;
                Ok(ack(format!("wrote {} bytes to {rel}", content.len())))
            }
            Verb::Exists => {
                let present = backend_exists(&target)?;
                Ok(ack(if present { "true" } else { "false" }.to_string()))
            }
            Verb::Delete => {
                backend_delete(&target)?;
                Ok(ack(format!("deleted {rel}")))
            }
            // `cap_action` returned `Some` only for the four content verbs above.
            other => Err(Error::Endpoint(format!(
                "file endpoint does not support the {other:?} verb"
            ))),
        }
    }

    fn name(&self) -> &str {
        "file"
    }

    fn describe(&self) -> Description {
        Description::new("file")
            .title("Capability-gated file/store")
            .summary(
                "Reads and writes files resolved relative to a jailed root. Two layers gate \
                 every request: the structural jail (no `..`, no absolute paths, symlink-safe) \
                 and the capability path-ACL (`urn:cap:fs:<read|write|delete>:<path>`, \
                 longest-prefix match, `-`-prefixed exclusions, default-deny). `Source` yields a \
                 string by default; `as=application/octet-stream` yields raw bytes.",
            )
            .verb(Verb::Source)
            .verb(Verb::Sink)
            .verb(Verb::Exists)
            .verb(Verb::Delete)
            .verb(Verb::Meta)
            .input(
                ArgSpec::new("path")
                    .summary("Path relative to the endpoint root (no `..`, no absolute paths)."),
            )
            .input(
                ArgSpec::new("content")
                    .summary("Bytes to write (Sink only)."),
            )
            .input(
                ArgSpec::new("as")
                    .summary("Requested representation type for Source (e.g. application/octet-stream for raw bytes)."),
            )
            .output("text/plain;charset=utf-8")
    }
}

/// The capability action a verb requires: reads (and existence checks) need
/// `read`, writes need `write`, deletes need `delete`. `Meta` is not an endpoint
/// concern (`None`).
fn cap_action(verb: Verb) -> Option<&'static str> {
    match verb {
        Verb::Source | Verb::Exists => Some("read"),
        Verb::Sink => Some("write"),
        Verb::Delete => Some("delete"),
        Verb::Meta => None,
    }
}

/// Whether `capability` grants `action` on `target`, by longest-prefix path-ACL.
///
/// `root` allows everything (the jail is the only remaining bound). Otherwise the
/// `urn:cap:fs:<action>:<path>` scopes are matched against `target`: the rule with
/// the longest directory that contains `target` decides, with deny winning ties,
/// and no match meaning deny.
fn cap_allows(capability: &Capability, action: &str, target: &Path) -> bool {
    if capability.is_root() {
        return true;
    }
    let Some(scopes) = capability.scopes() else {
        return false;
    };
    let prefix = format!("urn:cap:fs:{action}:");

    let mut best_len: Option<usize> = None;
    let mut allowed = false;
    for scope in scopes {
        let Some(rest) = scope.strip_prefix(&prefix) else {
            continue;
        };
        // A leading `-` marks a deny rule; the remainder is the directory/file.
        let (rule_allows, dir) = match rest.strip_prefix('-') {
            Some(d) => (false, d),
            None => (true, rest),
        };
        if !path_within(Path::new(dir), target) {
            continue;
        }
        let len = dir.len();
        match best_len {
            Some(b) if len < b => {} // a more specific rule already decided
            Some(b) if len == b => {
                // Tie on specificity: deny wins.
                allowed = allowed && rule_allows;
            }
            _ => {
                best_len = Some(len);
                allowed = rule_allows;
            }
        }
    }
    best_len.is_some() && allowed
}

/// Whether `target` is `dir` itself or sits beneath it (component-wise, so
/// `/a/b` is *not* within `/a/bc`).
fn path_within(dir: &Path, target: &Path) -> bool {
    target == dir || target.starts_with(dir)
}

/// The representation type for a `Source`: an explicit `as` override, else the
/// extension-guessed type, else — "strings by default" — `text/plain` when the
/// bytes are valid UTF-8, else raw bytes.
fn source_type(path: &Path, bytes: &[u8], as_override: Option<&str>) -> ReprType {
    if let Some(t) = as_override {
        return ReprType::new(t);
    }
    let guessed = media_type_for(path);
    if guessed.media_type != "application/octet-stream" {
        return guessed;
    }
    if std::str::from_utf8(bytes).is_ok() {
        ReprType::new("text/plain").with_param("charset", "utf-8")
    } else {
        guessed
    }
}

/// A short `text/plain` acknowledgement representation for mutating verbs.
fn ack(message: String) -> Representation {
    Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        message.into_bytes(),
    )
}

fn deny(detail: &str) -> Error {
    Error::InvalidArgument {
        name: "path".to_string(),
        detail: detail.to_string(),
    }
}

fn media_type_for(path: &Path) -> ReprType {
    let media = match path.extension().and_then(|e| e.to_str()) {
        Some("txt") => "text/plain",
        Some("md") => "text/markdown",
        Some("ttl") => "text/turtle",
        Some("nt") => "application/n-triples",
        Some("json") => "application/json",
        Some("jsonld") => "application/ld+json",
        Some("html") => "text/html",
        _ => "application/octet-stream",
    };
    ReprType::new(media)
}

// --- platform backend ------------------------------------------------------
//
// The jail and the capability ACL are platform-agnostic and run before any of
// these. Only the storage primitive differs per target.

/// Native backend: the jailed `std::fs`.
#[cfg(not(target_family = "wasm"))]
mod backend {
    use super::*;

    pub(super) fn read(path: &Path) -> Result<Vec<u8>> {
        std::fs::read(path).map_err(|e| Error::Endpoint(format!("read {}: {e}", path.display())))
    }

    pub(super) fn write(path: &Path, bytes: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Endpoint(format!("create {}: {e}", parent.display())))?;
        }
        std::fs::write(path, bytes)
            .map_err(|e| Error::Endpoint(format!("write {}: {e}", path.display())))
    }

    pub(super) fn exists(path: &Path) -> Result<bool> {
        Ok(path.exists())
    }

    pub(super) fn delete(path: &Path) -> Result<()> {
        std::fs::remove_file(path)
            .map_err(|e| Error::Endpoint(format!("delete {}: {e}", path.display())))
    }
}

/// wasm32 backend: the browser's `localStorage`, with the jailed target path
/// mapped to a namespaced key (`ikigai:fs:<path>`) so several mounts/roots
/// coexist in one origin's store. The jail and capability ACL have already run by
/// the time these are called — only the storage primitive differs from native.
///
/// `localStorage` holds UTF-16 strings, so this backend is text-oriented: a write
/// of non-UTF-8 bytes is refused (binary would need an encoding such as base64 —
/// a later step). The REPL's `sink`/`source` are text, which is the intended use.
#[cfg(target_family = "wasm")]
mod backend {
    use super::*;

    /// The `localStorage` key for a jailed target path.
    fn key(path: &Path) -> String {
        format!("ikigai:fs:{}", path.display())
    }

    /// This origin's `localStorage`, or an error if it isn't available (no window,
    /// or storage disabled).
    fn storage() -> Result<web_sys::Storage> {
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .ok_or_else(|| Error::Endpoint("localStorage is unavailable in this context".into()))
    }

    pub(super) fn read(path: &Path) -> Result<Vec<u8>> {
        let value = storage()?
            .get_item(&key(path))
            .map_err(|_| Error::Endpoint(format!("read {}: localStorage error", path.display())))?;
        match value {
            Some(text) => Ok(text.into_bytes()),
            None => Err(Error::Endpoint(format!(
                "read {}: no such item",
                path.display()
            ))),
        }
    }

    pub(super) fn write(path: &Path, bytes: &[u8]) -> Result<()> {
        let text = std::str::from_utf8(bytes).map_err(|_| {
            Error::Endpoint(format!(
                "write {}: the localStorage backend stores UTF-8 text (binary needs base64)",
                path.display()
            ))
        })?;
        storage()?.set_item(&key(path), text).map_err(|_| {
            Error::Endpoint(format!(
                "write {}: localStorage error (quota?)",
                path.display()
            ))
        })
    }

    pub(super) fn exists(path: &Path) -> Result<bool> {
        Ok(storage()?
            .get_item(&key(path))
            .map_err(|_| Error::Endpoint(format!("exists {}: localStorage error", path.display())))?
            .is_some())
    }

    pub(super) fn delete(path: &Path) -> Result<()> {
        storage()?
            .remove_item(&key(path))
            .map_err(|_| Error::Endpoint(format!("delete {}: localStorage error", path.display())))
    }
}

fn backend_read(path: &Path) -> Result<Vec<u8>> {
    backend::read(path)
}
fn backend_write(path: &Path, bytes: &[u8]) -> Result<()> {
    backend::write(path, bytes)
}
fn backend_exists(path: &Path) -> Result<bool> {
    backend::exists(path)
}
fn backend_delete(path: &Path) -> Result<()> {
    backend::delete(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{Bindings, Iri, Request};
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_root() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ikigai-fs-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Invoke a verb with the given `path` binding under `cap`, optionally with a
    /// `content`/`as` argument.
    fn invoke(
        ep: &FileEndpoint,
        verb: Verb,
        path: &str,
        cap: &Capability,
        args: &[(&str, &[u8])],
    ) -> Result<Representation> {
        let mut req = Request::new(verb, Iri::parse("urn:file:default").unwrap());
        for (name, value) in args {
            req = req.with_arg(*name, ikigai_core::ArgRef::Inline(value.to_vec()));
        }
        let mut bindings = Bindings::new();
        bindings.insert("path", path);
        let inv = Invocation::detached(&req, &bindings, cap);
        block_on(ep.invoke(&inv))
    }

    /// A capability scoped to the given fs scopes.
    fn cap(scopes: &[&str]) -> Capability {
        Capability::scoped(scopes.iter().map(|s| s.to_string()))
    }

    fn read_scope(root: &Path) -> String {
        format!("urn:cap:fs:read:{}", root.display())
    }
    fn write_scope(root: &Path) -> String {
        format!("urn:cap:fs:write:{}", root.display())
    }

    #[test]
    fn root_capability_reads_a_text_file_as_a_string() {
        let root = temp_root();
        std::fs::write(root.join("hello.txt"), b"hi there").unwrap();
        let ep = FileEndpoint::new(&root);
        let rep = invoke(&ep, Verb::Source, "hello.txt", &Capability::root(), &[]).unwrap();
        assert_eq!(rep.repr_type.media_type, "text/plain");
        assert_eq!(rep.bytes, b"hi there");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn extensionless_utf8_defaults_to_a_string() {
        let root = temp_root();
        std::fs::write(root.join("note"), b"plain words").unwrap();
        let ep = FileEndpoint::new(&root);
        let rep = invoke(&ep, Verb::Source, "note", &Capability::root(), &[]).unwrap();
        assert_eq!(rep.repr_type.media_type, "text/plain");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn as_octet_stream_forces_raw_bytes() {
        let root = temp_root();
        std::fs::write(root.join("hello.txt"), b"hi").unwrap();
        let ep = FileEndpoint::new(&root);
        let rep = invoke(
            &ep,
            Verb::Source,
            "hello.txt",
            &Capability::root(),
            &[("as", b"application/octet-stream")],
        )
        .unwrap();
        assert_eq!(rep.repr_type.media_type, "application/octet-stream");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn read_capability_grants_reads_within_the_root() {
        let root = temp_root();
        std::fs::write(root.join("ok.txt"), b"yes").unwrap();
        let ep = FileEndpoint::new(&root);
        let c = cap(&[&read_scope(&root)]);
        let rep = invoke(&ep, Verb::Source, "ok.txt", &c, &[]).unwrap();
        assert_eq!(rep.bytes, b"yes");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_empty_capability_is_denied() {
        let root = temp_root();
        std::fs::write(root.join("ok.txt"), b"yes").unwrap();
        let ep = FileEndpoint::new(&root);
        let err = invoke(&ep, Verb::Source, "ok.txt", &cap(&[]), &[]).unwrap_err();
        assert!(matches!(err, Error::Endpoint(_)));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn read_capability_does_not_grant_writes() {
        let root = temp_root();
        let ep = FileEndpoint::new(&root);
        let c = cap(&[&read_scope(&root)]);
        let err = invoke(&ep, Verb::Sink, "new.txt", &c, &[("content", b"x")]).unwrap_err();
        assert!(matches!(err, Error::Endpoint(_)));
        assert!(!root.join("new.txt").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn write_capability_sinks_and_then_sources_back() {
        let root = temp_root();
        let ep = FileEndpoint::new(&root);
        let c = cap(&[&read_scope(&root), &write_scope(&root)]);
        invoke(
            &ep,
            Verb::Sink,
            "notes.txt",
            &c,
            &[("content", b"remember this")],
        )
        .unwrap();
        let rep = invoke(&ep, Verb::Source, "notes.txt", &c, &[]).unwrap();
        assert_eq!(rep.bytes, b"remember this");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn exclusion_denies_a_subtree_while_the_parent_is_granted() {
        let root = temp_root();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("open.txt"), b"public").unwrap();
        std::fs::write(root.join("secret/k.txt"), b"private").unwrap();
        let ep = FileEndpoint::new(&root);
        let c = cap(&[
            &read_scope(&root),
            &format!("urn:cap:fs:read:-{}", root.join("secret").display()),
        ]);
        // parent grant applies to the open file
        assert!(invoke(&ep, Verb::Source, "open.txt", &c, &[]).is_ok());
        // the longer deny wins for anything under `secret`
        assert!(invoke(&ep, Verb::Source, "secret/k.txt", &c, &[]).is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn longer_allow_reopens_an_excluded_subtree() {
        let root = temp_root();
        let secret = root.join("secret");
        let shared = secret.join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::write(shared.join("ok.txt"), b"reshared").unwrap();
        std::fs::write(secret.join("k.txt"), b"private").unwrap();
        let ep = FileEndpoint::new(&root);
        let c = cap(&[
            &read_scope(&root),
            &format!("urn:cap:fs:read:-{}", secret.display()),
            &format!("urn:cap:fs:read:{}", shared.display()),
        ]);
        assert!(invoke(&ep, Verb::Source, "secret/k.txt", &c, &[]).is_err());
        assert!(invoke(&ep, Verb::Source, "secret/shared/ok.txt", &c, &[]).is_ok());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn the_jail_rejects_traversal_before_the_capability() {
        let root = temp_root();
        let ep = FileEndpoint::new(&root);
        // even with a root capability, the jail denies `..`
        let err = invoke(&ep, Verb::Source, "../escape", &Capability::root(), &[]).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument { .. }));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn exists_and_delete_are_capability_gated() {
        let root = temp_root();
        std::fs::write(root.join("gone.txt"), b"x").unwrap();
        let ep = FileEndpoint::new(&root);
        let read_only = cap(&[&read_scope(&root)]);
        // exists is a read
        assert_eq!(
            invoke(&ep, Verb::Exists, "gone.txt", &read_only, &[])
                .unwrap()
                .bytes,
            b"true"
        );
        // delete needs the delete action — read-only is refused
        assert!(invoke(&ep, Verb::Delete, "gone.txt", &read_only, &[]).is_err());
        assert!(root.join("gone.txt").exists());
        // with delete, it goes
        let deleter = cap(&[&format!("urn:cap:fs:delete:{}", root.display())]);
        assert!(invoke(&ep, Verb::Delete, "gone.txt", &deleter, &[]).is_ok());
        assert!(!root.join("gone.txt").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn space_mounts_the_grammar_and_resolves_a_path() {
        use ikigai_core::Kernel;
        use std::sync::Arc;
        let root = temp_root();
        std::fs::write(root.join("page.txt"), b"hello from a space").unwrap();
        let kernel = Kernel::new(Arc::new(space(&root)));
        let rep = block_on(kernel.issue(
            Request::new(Verb::Source, Iri::parse("urn:file:page.txt").unwrap()),
            &Capability::root(),
        ))
        .unwrap();
        assert_eq!(rep.bytes, b"hello from a space");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn default_space_does_not_cache_reads() {
        use ikigai_core::Kernel;
        use std::sync::Arc;
        let root = temp_root();
        std::fs::write(root.join("live.txt"), b"x").unwrap();
        let kernel = Kernel::new(Arc::new(space(&root)));
        let cap = Capability::root();
        let source = Request::new(Verb::Source, Iri::parse("urn:file:live.txt").unwrap());
        block_on(kernel.issue(source.clone(), &cap)).unwrap();
        assert!(
            !kernel.is_cached(&source),
            "the default file mode is uncacheable (a live fact)"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cacheable_space_caches_reads_until_a_sink_cuts_them() {
        use ikigai_core::Kernel;
        use std::sync::Arc;
        let root = temp_root();
        std::fs::write(root.join("notes.txt"), b"v1").unwrap();
        let kernel = Kernel::new(Arc::new(cacheable_space(&root)));
        let cap = Capability::root();
        let source = || Request::new(Verb::Source, Iri::parse("urn:file:notes.txt").unwrap());

        // Read v1; the cacheable mode caches it under the `urn:file:notes.txt` thread.
        assert_eq!(block_on(kernel.issue(source(), &cap)).unwrap().bytes, b"v1");
        assert!(kernel.is_cached(&source()), "cacheable source is cached");

        // Write v2 through the kernel: the Sink auto-cuts `urn:file:notes.txt`.
        let sink = Request::new(Verb::Sink, Iri::parse("urn:file:notes.txt").unwrap())
            .with_arg("content", ikigai_core::ArgRef::Inline(b"v2".to_vec()));
        block_on(kernel.issue(sink, &cap)).unwrap();
        assert!(
            !kernel.is_cached(&source()),
            "the write invalidated the cached read"
        );

        // Read again: the cache recomputes and sees v2.
        assert_eq!(block_on(kernel.issue(source(), &cap)).unwrap().bytes, b"v2");
        std::fs::remove_dir_all(&root).ok();
    }
}

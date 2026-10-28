//! `ikigai-fs` — a capability-gated file/store module.
//!
//! A standalone **ikigai module crate** (like `ikigai-fn` / `ikigai-personal`):
//! a host links it in and mounts [`space`], rather than the engine shipping file
//! behavior itself. It depends only on the published `ikigai-core` kernel.
//!
//! Files are the most dangerous endpoint in the system — arbitrary filesystem
//! read *and* write — so access is confined by **two independent layers, both
//! required on every request**, and both judge **the file actually opened**:
//!
//! 1. **The jail (structural, set at mount time).** [`FileEndpoint::new`] is
//!    handed a `root` directory and will never serve a file outside it. The
//!    request path is resolved component by component from an open handle on the
//!    root, never following a symbolic link (`openat` with `O_NOFOLLOW`), and the
//!    read uses the checked file handle; a write stages and atomically publishes
//!    through the checked parent directory handle. A root that cannot be opened
//!    serves nothing (fail closed). Even a `root` capability cannot escape it.
//! 2. **The capability path-ACL (dynamic, per request).** The invocation's
//!    [`Capability`] must grant the request's action for the resolved path. A
//!    capability bug can never punch through the jail; the capability scopes
//!    *within* it.
//!
//! ## One file, one name
//!
//! The endpoint serves a file under exactly one spelling: the path as it is on
//! disk, relative to the root. It refuses (`InvalidArgument`, a refusal no retry
//! changes) every other way to name the same file:
//!
//! - **a symbolic link anywhere in the path** — the leaf or any directory, in the
//!   jail or out of it. A link would make the file opened differ from the path
//!   authorized, which is the whole of the round-3 audit's ACL bypasses;
//! - **a non-canonical spelling** — `./notes.txt`, `a//b`, a trailing `/` (the
//!   error names the canonical one), `..`, or an absolute path;
//! - **a spelling the volume folds onto another name** — `NOTES.txt` for
//!   `notes.txt` on a case-insensitive (or normalization-insensitive) volume;
//! - **a name with another meaning on Windows**, on every platform — a `\`, a `:`
//!   (a drive prefix such as `C:x`, which `Path::join` there lets replace the base,
//!   or a data stream), a trailing `.` or space (stripped there), or a device name
//!   (`CON`, `aux.c`, `COM1`), so a `urn:file:` name means one file wherever it is
//!   served.
//!
//! So the request IRI *is* the file's identity: the ACL judges the path that is
//! opened, and the golden thread a read hangs from is the one every write to that
//! file cuts (the kernel auto-cuts a write's own target). Hard links remain
//! distinct names; a Sink replaces only its target name with a new inode.
//!
//! ## The capability path-ACL
//!
//! A file capability is carried as `urn:cap:` scopes of the form
//! `urn:cap:fs:<action>:<path>`, where `<action>` is `read` / `write` / `delete`
//! and `<path>` is a directory or file. A leading `-` on the path marks a
//! **deny** (exclusion):
//!
//! - `urn:cap:fs:read:/Users/brian/workspace` — read anything under that dir.
//! - `urn:cap:fs:read:/Users/brian/workspace/public` (only) — an allowlist: read
//!   just that subtree, not the parent.
//! - `urn:cap:fs:read:/Users/brian/workspace` **+** `urn:cap:fs:read:-/Users/brian/workspace/secret`
//!   — read the tree *except* `secret`.
//!
//! A scope is mapped into the jail before it is matched: its path is normalized
//! (`.`, repeated and trailing `/` dropped), placed against the root under either
//! of the root's spellings — as mounted, or canonical (`/private/var/…` for
//! `/var/…`) — and the part inside the jail is resolved to its on-disk names. A
//! scope naming the root or an ancestor of it covers the whole jail.
//!
//! Matching is **most specific wins, by path depth**, with **deny breaking
//! ties**: for an `(action, path)`, the deepest rule whose directory contains the
//! path decides; if a deny ties it, it's denied. No matching rule →
//! **default-deny**. A `root` capability allows everything *within the jail*.
//! Where a deny names something not on disk, it is compared without regard to
//! case, since the volume's rule for a name that does not exist cannot be read
//! off the volume; that can only over-deny. These are owner-minted rule sets — the
//! flat-scope [`Capability`] is untouched; this module does the path-aware
//! matching, where path semantics belong.
//!
//! **A `-path` deny survives attenuation and a transport clamp** (since ikigai-core
//! 0.1.86, ledger #858). A deny is a deny-shaped scope (`ikigai_core::is_deny_scope`),
//! and core's `attenuate` and `clamp` keep every deny either side holds, so a delegate
//! attenuated to `{read:/ws}` from `{read:/ws, read:-/ws/secret}` still cannot read
//! `secret`, and neither can a peer clamped the same way. `tests/audit_regressions.rs`
//! pins it (`b3_a_deny_survives_attenuation_and_clamp`).
//!
//! ## Representations
//!
//! `Source` hands back a **string by default** (a known text media type from the
//! extension, or `text/plain` when the bytes decode as UTF-8); pass `as` =
//! `application/octet-stream` to get the raw **bytes** instead. Any other `as` is
//! refused: this endpoint does not convert, so it will not relabel. `Sink` writes
//! UTF-8 `content` by default, or decodes it to bytes with `encoding=base64`.
//! On Unix, Sink syncs a same-directory staging file before atomic publication,
//! so readers see complete old or new content and a failed staging write leaves
//! the target intact. Replacement preserves ordinary permission bits, but not
//! ownership, extended attributes, or hard-link identity. It requires write
//! access to the parent directory. A killed process can leave an unpublished
//! staging file; directory-entry durability across a power loss is not
//! guaranteed. A missing file is the typed [`Error::NotFound`]. Errors name the
//! request's IRI, never a host path. Reads
//! (and `Exists` answers) are **uncacheable by default** — a file is a live fact —
//! but a mount can opt into caching them under a **golden thread**
//! ([`FileEndpoint::cacheable`] / [`cacheable_space`]): a `Sink`/`Delete` through
//! the kernel then invalidates the cached read (requires `ikigai-core` ≥ 0.1.9).
//!
//! The module passes `ikigai-conformance` (`tests/conformance.rs`) on both
//! mounts, with no opt-outs.
//!
//! Native file `Source` reads through [`Endpoint::invoke`] (the bytes path) are
//! limited to [`MAX_FILE_SOURCE_BYTES`] (16 MiB). Larger files are refused with
//! [`Error::OverBudget`], never truncated.
//!
//! ## Bodies
//!
//! On the native backend a `Source` also answers a seekable [`Body::Replay`]
//! ([`Endpoint::invoke_body`], what the kernel calls), backed by the file and not
//! bound by [`MAX_FILE_SOURCE_BYTES`]: a caller that collects it is bounded by its
//! run's byte budget. Each reader opens a fresh descriptor through the jailed,
//! no-follow walk, reads chunks of at most 64 KiB, and ends in
//! [`Error::Conflict`] when the file changed while read, never a short or mixed
//! body. A `Sink` reads its content with [`Invocation::content_body`] and writes
//! it chunk by chunk into the staging file, decoding UTF-8 and base64
//! incrementally; a stream that fails part-way leaves the target untouched. The
//! `Sink` action declares `content` [`ArgSpec::reads_body`], so a body a host
//! attaches streams into the staging file rather than being collected by the
//! kernel first (ledger #2469). The `wasm32` `localStorage` backend keeps
//! answering a buffer, and collects a `Sink`'s content under the run's byte budget.
//!
//! A file body states a strong validator (ledger #2474): the [`ContentId`] of its
//! bytes, so an HTTP door can send an `ETag`, `304` and byte ranges for it. The
//! digest costs one full read, done the first time it is asked for and remembered
//! process-wide against the file's version (device, inode, size, and nanosecond
//! mtime and ctime); asked again of the same version, it is a lookup. A file whose
//! last change is less than [`VALIDATOR_SETTLE`] old states none yet.
//!
//! [`ContentId`]: ikigai_core::ContentId
//!
//! ## Spilling
//!
//! On Unix, [`FileSpill`] is the file-backed spill facility (ledger #2241): a host
//! installs it with [`Kernel::with_spill`](ikigai_core::Kernel::with_spill), over a
//! directory the host supplies, and `urn:stream:spill` then writes a one-shot body to
//! a file there and answers it as a seekable body known by its content id, removed
//! when its last holder drops it. The `wasm32` backend installs no facility.
//!
//! ## Platforms
//!
//! One crate, a `cfg`-gated backend. The native backend (Unix) resolves through
//! `openat` on directory handles (via `rustix`); the `wasm32` backend stores in
//! the browser's `localStorage` (keyed `ikigai:fs:<root>/<path>`), so the same
//! module — same `file:` contract, same capability scopes — links into a native
//! CLI and an in-browser host alike. `localStorage` has no links and no case
//! folding, so there the spelling rules are the whole jail. The `localStorage`
//! backend is text-oriented (it refuses non-UTF-8 writes). Any other native
//! platform has no handle-relative walk here and **refuses every request**
//! rather than serve one unconfined.

#[cfg(unix)]
mod spill;
#[cfg(unix)]
pub use spill::{FileSpill, SPILL_PREFIX};

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, ArgSpec, Body, Capability, Description, Endpoint, EndpointSpace, Error,
    FailureClass, Invocation, ReprType, Representation, Result, UriTemplate, Verb,
};

/// The conventional grammar a host mounts this module at: `urn:file:{path}`,
/// where `{path}` is captured root-relative and handed to the endpoint as the
/// `path` binding (so the file's *identity* is the request, not an argument).
pub const FILE_TEMPLATE: &str = "urn:file:{path}";

/// Maximum native file payload returned by a `Source`: 16 MiB.
///
/// The opened file's metadata is checked before reading, and the read itself is
/// bounded in case the file grows. Exceeding this limit returns
/// [`Error::OverBudget`]; a partial representation is never returned.
/// This bounds each read, not the aggregate memory held by concurrent requests
/// or cached representations. Browser localStorage uses its own storage quota.
pub const MAX_FILE_SOURCE_BYTES: u64 = 16 * 1024 * 1024;

/// How old a file's last change (its ctime) must be before its body states a
/// validator: 2 s.
///
/// The validator is the digest of the bytes, remembered against the file's
/// version, which is only as fine as the file system's timestamps. A second
/// same-length write within the same timestamp tick as the first leaves the
/// version unchanged, so a digest taken between them would be stale with nothing
/// to show it (git's "racily clean" index entries). Past this much time any later
/// write gets a later ctime; inside it the body states no validator, and a door
/// serves it whole, without an `ETag`, as before. Two seconds covers the coarsest
/// common granularity (FAT's two-second times) and small clock skew to a network
/// file server.
pub const VALIDATOR_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);

/// The datatype every input of this module carries: a root-relative path, a
/// media type, encoding, and content all arrive as strings on the wire and in
/// an agent's tool call. Binary content is expressed with `encoding=base64`.
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

/// The one `as` a `Source` honors: the raw bytes, unlabeled.
const OCTET_STREAM: &str = "application/octet-stream";

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

/// Like [`space`], but **caches** `Source` reads and `Exists` answers under golden
/// threads (see [`FileEndpoint::cacheable`]). A `Sink`/`Delete` through the kernel
/// invalidates them; suitable for a root written through ikigai. Requires a host
/// kernel that auto-cuts on writes (`ikigai-core` ≥ 0.1.9).
pub fn cacheable_space(root: impl Into<PathBuf>) -> EndpointSpace {
    EndpointSpace::new().bind(
        UriTemplate::parse(FILE_TEMPLATE).expect("FILE_TEMPLATE is a valid template"),
        FileEndpoint::new(root).cacheable(),
    )
}

/// The most bytes one `Sink` may write under a root that sets no ceiling of its own
/// ([`FileEndpoint::max_write`]): 64 MiB, the wire's upload bound (ledger #2493).
pub const DEFAULT_MAX_WRITE: u64 = 64 << 20;

/// A file endpoint jailed to a root directory, gated by the capability path-ACL.
pub struct FileEndpoint {
    root: PathBuf,
    cacheable: bool,
    max_write: u64,
}

impl FileEndpoint {
    /// A file endpoint that will only ever serve paths within `root` (the jail).
    ///
    /// The root is opened on every request, following any links in `root` itself
    /// (it is the host's configuration, not the caller's input); a root that does
    /// not exist or cannot be opened makes every request fail, and is never
    /// created.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        FileEndpoint {
            root: root.into(),
            cacheable: false,
            max_write: DEFAULT_MAX_WRITE,
        }
    }

    /// The most bytes one `Sink` may write under this root ([`DEFAULT_MAX_WRITE`] unless
    /// set), counted after decoding, whatever the content arrived as (inline, a content
    /// id, or a body streamed to disk). It is the root's bound because the disk is the
    /// host's: a streamed body is never collected under the run's byte budget, so without
    /// it a pipe could fill the disk (ledger #2493). A write past it is refused with
    /// [`Error::OverBudget`] part-way, never truncated, and leaves nothing behind: the old
    /// target or none, and no staging file.
    pub fn max_write(mut self, bytes: u64) -> Self {
        self.max_write = bytes;
        self
    }

    /// Cache `Source` reads and `Exists` answers under a golden thread (opt-in).
    ///
    /// By default a file is a *live fact* — every read recomputes — so a change
    /// made outside ikigai is always seen. Opt in to caching: each read (and each
    /// existence check) is stored under the thread named after the resource (its
    /// IRI, which is the file's one name — see the crate docs), and a
    /// `Sink`/`Delete` through the kernel auto-cuts it, so writes invalidate
    /// correctly. **Caveat:** out-of-band changes (an editor, another process) are
    /// not seen until a kernel-mediated write — or an external watcher — cuts the
    /// thread. A cached read's body ([`Endpoint::invoke_body`]) is never stale
    /// bytes: once the file changed out of band, its readers end in
    /// [`Error::Conflict`] until the thread is cut. Enable only where that window
    /// is acceptable (e.g. a root written through ikigai), until the watch policy
    /// lands.
    pub fn cacheable(mut self) -> Self {
        self.cacheable = true;
        self
    }
}

/// A request that passed both layers of the jail: the walk's result and what
/// the verb needs to be served.
struct Admitted<'a> {
    rel: &'a str,
    iri: &'a str,
    leaf: &'a str,
    raw: bool,
    found: backend::Found,
}

impl FileEndpoint {
    /// Both layers, in order, for every verb: the lexical rules, the capability
    /// path-ACL, then the walk from the opened root.
    fn admit<'a>(&self, inv: &'a Invocation<'_>) -> Result<Admitted<'a>> {
        let rel = inv
            .bindings
            .get("path")
            .ok_or_else(|| Error::MissingArgument("path".to_string()))?;
        // Every message names the request's own IRI, never the host path behind it.
        let iri = inv.request.target.as_str();

        // Layer 1, lexical half: the path's one spelling. No filesystem access yet.
        let names = canonical_names(rel)?;
        let verb = inv.request.verb;
        let action = cap_action(verb).ok_or_else(|| {
            Error::Endpoint(format!("file endpoint does not support the {verb:?} verb"))
        })?;
        let raw = if verb == Verb::Source {
            wants_raw_bytes(inv)?
        } else {
            false
        };

        // The jail's anchor. Fails CLOSED: a root that cannot be opened serves
        // nothing (it used to skip containment altogether).
        let jail = backend::Jail::open(&self.root, iri)?;

        // Layer 2 — the capability path-ACL, judged on the names the walk below
        // will open. It runs before the walk touches the request's path, so a
        // refusal says nothing about what is or is not there; and because the walk
        // refuses any path whose opened file is not exactly these names (a link, a
        // folded spelling), the path judged here is the path opened.
        if !cap_allows(inv.capability, action, &self.root, &jail, &names) {
            // Typed `Denied` — a permanent authority failure the trace, manifold,
            // and wire recognize as a 403-equivalent without sniffing message text.
            return Err(Error::Denied(format!(
                "capability does not grant `{action}` on `{rel}`"
            )));
        }

        // Layer 1, structural half: walk the names from the root handle.
        let found = jail.probe(&names, iri)?;
        Ok(Admitted {
            rel,
            iri,
            leaf: names.last().copied().unwrap_or_default(),
            raw,
            found,
        })
    }

    /// A read's answer, cached under the file's golden thread when the mount
    /// opted in.
    fn source_answer<B>(&self, repr: Representation<B>, iri: &str) -> Representation<B> {
        if self.cacheable {
            // Cache under a golden thread named after the resource. A
            // `Sink`/`Delete` (kernel auto-cut) — or an external watcher —
            // invalidates it. The IRI is the file's only name (aliases are
            // refused above), so the write that changes the file is the one
            // that cuts this thread. All representations of the file
            // (string, raw bytes, body) share it.
            repr.cacheable().depends_on(iri)
        } else {
            // Default: a file is a live fact, recomputed every read.
            repr
        }
    }
}

#[async_trait]
impl Endpoint for FileEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let Admitted {
            rel,
            iri,
            leaf,
            raw,
            found,
        } = self.admit(inv)?;
        match inv.request.verb {
            Verb::Source => {
                let bytes = found.read(iri)?;
                let repr = Representation::new(source_type(leaf, &bytes, raw), bytes);
                Ok(self.source_answer(repr, iri))
            }
            Verb::Sink => {
                let written = sink(inv, found, iri, self.max_write).await?;
                Ok(ack(format!("wrote {written} bytes to {rel}")))
            }
            Verb::Exists => {
                let present = found.exists();
                let repr = ack(if present { "true" } else { "false" }.to_string());
                if self.cacheable {
                    // The same thread as the read: an existence answer is a
                    // representation of the file too, and the `Sink`/`Delete`
                    // that changes it is the one that cuts the thread.
                    Ok(repr.cacheable().depends_on(iri))
                } else {
                    Ok(repr)
                }
            }
            Verb::Delete => {
                found.delete(iri)?;
                Ok(ack(format!("deleted {rel}")))
            }
            // `cap_action` returned `Some` only for the four content verbs above.
            other => Err(Error::Endpoint(format!(
                "file endpoint does not support the {other:?} verb"
            ))),
        }
    }

    /// On the native backend a `Source` answers a seekable [`Body::Replay`]
    /// backed by the file, not bound by [`MAX_FILE_SOURCE_BYTES`] (the caller's
    /// run budget bounds whatever it collects). Each reader opens a fresh handle
    /// through the same jailed, no-follow walk, reads chunks of at most 64 KiB,
    /// and ends in [`Error::Conflict`] when the file changed while read. Every
    /// other verb, and every verb on the `localStorage` backend, answers as
    /// [`invoke`](Endpoint::invoke) does.
    async fn invoke_body(&self, inv: &Invocation<'_>) -> Result<Representation<Body>> {
        #[cfg(unix)]
        if inv.request.verb == Verb::Source {
            let Admitted {
                iri,
                leaf,
                raw,
                found,
                ..
            } = self.admit(inv)?;
            let (repr_type, body) = found.body(leaf, raw, iri)?;
            return Ok(self.source_answer(Representation::from_body(repr_type, body), iri));
        }
        self.invoke(inv).await.map(Representation::into_body)
    }

    fn name(&self) -> &str {
        "file"
    }

    fn describe(&self) -> Description {
        Description::new("file")
            .title("Capability-gated file/store")
            .summary(
                "Reads and writes files resolved relative to a jailed root. Two layers gate \
                 every request: the structural jail (the path is walked from the root without \
                 following links; `..`, absolute paths, links and any spelling but the on-disk \
                 one are refused) and the capability path-ACL \
                 (`urn:cap:fs:<read|write|delete>:<path>`, deepest rule wins, `-`-prefixed \
                 exclusions win ties, default-deny). `Source` yields a string by default; \
                 `as=application/octet-stream` yields raw bytes; a missing file is NotFound.",
            )
            .verb(Verb::Source)
            .verb(Verb::Sink)
            .verb(Verb::Exists)
            .verb(Verb::Delete)
            .verb(Verb::Meta)
            .input(
                ArgSpec::new("path")
                    .summary(
                        "Path relative to the endpoint root, spelled as on disk (no `.`, `..`, \
                         empty segments, absolute paths or links).",
                    )
                    .class(XSD_STRING)
                    .binding(),
            )
            .input(
                ArgSpec::new("content")
                    .summary("UTF-8 text, or standard padded base64 when encoding=base64 (Sink only).")
                    .class(XSD_STRING)
                    .optional(),
            )
            .input(sink_encoding_arg())
            .input(
                ArgSpec::new("as")
                    .summary("Source only: application/octet-stream for raw bytes; nothing else is accepted.")
                    .class(XSD_STRING)
                    .one_of([OCTET_STREAM])
                    .optional(),
            )
            .output("text/plain;charset=utf-8")
            // Per-verb contracts: the path-ACL is parameterized
            // (urn:cap:fs:<action>:<path>), so each action declares the wildcard
            // form — "holds SOME grant under this prefix" — for selection; the
            // exact target is still checked against the ACL at invoke time.
            .action(
                ActionSpec::new(Verb::Source)
                    .summary("read a file within the jail")
                    .requires("urn:cap:fs:read:*")
                    .input(
                        ArgSpec::new("path")
                            .summary("relative to the jailed root")
                            .class(XSD_STRING)
                            .binding(),
                    )
                    .input(
                        ArgSpec::new("as")
                            .summary("application/octet-stream for raw bytes")
                            .class(XSD_STRING)
                            .one_of([OCTET_STREAM])
                            // Omitted: a string by default. No `default_value`,
                            // because the default is not one media type but
                            // "the extension's, else text/plain when UTF-8".
                            .optional(),
                    )
                    .output("text/plain;charset=utf-8")
                    .output(OCTET_STREAM)
                    // `permanent`: a refused path, a missing file, and the
                    // `Conflict` a body ends with when the file changed while
                    // read. `over-budget`: the bytes path's 16 MiB bound.
                    // `unknown`: an I/O failure.
                    .fails(FailureClass::Permanent)
                    .fails(FailureClass::OverBudget)
                    .fails(FailureClass::Unknown),
            )
            .action(
                ActionSpec::new(Verb::Exists)
                    .summary("test for a file (a read)")
                    .requires("urn:cap:fs:read:*")
                    .input(
                        ArgSpec::new("path")
                            .summary("relative to the jailed root")
                            .class(XSD_STRING)
                            .binding(),
                    )
                    .output("text/plain;charset=utf-8"),
            )
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("write a file within the jail")
                    .requires("urn:cap:fs:write:*")
                    .input(
                        ArgSpec::new("path")
                            .summary("relative to the jailed root")
                            .class(XSD_STRING)
                            .binding(),
                    )
                    // Read as a body (ledger #2469): an attached body streams into
                    // the staging file instead of being collected by the kernel first.
                    // Part of the contract, so it moved the Sink's contract IRI.
                    .input(
                        ArgSpec::new("content")
                            .summary("UTF-8 text, or standard padded base64 when encoding=base64")
                            .class(XSD_STRING)
                            .reads_body(),
                    )
                    .input(sink_encoding_arg())
                    .output("text/plain;charset=utf-8")
                    // `permanent`: refused content or path, a `Conflict` from a
                    // streamed content's source. `over-budget`: content past a
                    // bound, the root's `max_write` among them. `unknown`: an I/O failure.
                    .fails(FailureClass::Permanent)
                    .fails(FailureClass::OverBudget)
                    .fails(FailureClass::Unknown),
            )
            .action(
                ActionSpec::new(Verb::Delete)
                    .summary("delete a file within the jail")
                    .requires("urn:cap:fs:delete:*")
                    .input(
                        ArgSpec::new("path")
                            .summary("relative to the jailed root")
                            .class(XSD_STRING)
                            .binding(),
                    )
                    .output("text/plain;charset=utf-8"),
            )
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

/// Split a request path into its names, or refuse it: the lexical half of the jail.
///
/// A path is accepted only in its one canonical spelling — `/`-separated names, none
/// empty, none `.` or `..`, not absolute, none with another meaning on Windows
/// ([`windows_meaning`]) — so two IRIs can never name one file through spelling alone. A
/// refusal of a non-canonical spelling names the canonical one.
fn canonical_names(rel: &str) -> Result<Vec<&str>> {
    let names: Vec<&str> = rel.split('/').collect();
    if names.contains(&"..") {
        return Err(deny("parent-directory (`..`) segments are not allowed"));
    }
    if rel.starts_with('/') {
        return Err(deny("absolute paths are not allowed"));
    }
    if rel.contains('\0') {
        return Err(deny("a path cannot contain NUL"));
    }
    let kept: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| !n.is_empty() && *n != ".")
        .collect();
    if kept.is_empty() {
        return Err(deny("an empty path names the jail root, not a file"));
    }
    // Before the canonical-spelling hint, so the hint never names a refused path.
    for name in &kept {
        if let Some(why) = windows_meaning(name) {
            return Err(deny(&format!(
                "`{name}` {why}, so it is refused on every platform: a `urn:file:` name \
                 means one file wherever it is served"
            )));
        }
    }
    if kept.len() != names.len() {
        return Err(deny(&format!(
            "`{rel}` is not a canonical spelling (no `.`, empty segments or trailing `/`); \
             name the file `{}`",
            kept.join("/")
        )));
    }
    Ok(names)
}

/// Why one path segment would mean something else on Windows, or `None` when it is one
/// ordinary directory entry on every platform (ledger #1319).
///
/// On Windows `Path::join` with a drive-prefixed name (`C:x`) REPLACES the base, `\` is a
/// separator, a `:` names a drive or an NTFS stream (`notes.txt::$DATA` opens
/// `notes.txt`), a trailing `.` or space is stripped (`notes.txt.` opens `notes.txt`, past
/// a deny on it), and `CON`, `aux.c` and their kin name devices. Each is a legal file name
/// on Unix, and refused there too: a name that is one file on macOS and another path on
/// Windows is not a name to serve.
///
/// The rule is ikigai-cli's `ikigai_resolve::is_plain_file_name` (ledger #1307) applied to
/// each segment, copied rather than depended on: ledger #1320 decides where the shared rule
/// lives, and a host crate is no dependency for a module to take for one function. Keep the
/// two in step until then. Empty, `.`, `..`, `/` and NUL are refused by
/// [`canonical_names`] before this runs, and are refused here too so the rule stands alone.
fn windows_meaning(name: &str) -> Option<&'static str> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Some("is not one path segment");
    }
    if name.contains('\\') {
        return Some("contains `\\`, a path separator on Windows");
    }
    if name.contains(':') {
        return Some("contains `:`, which names a drive or a data stream on Windows");
    }
    if name.ends_with(['.', ' ']) {
        return Some("ends in `.` or a space, which Windows strips, so it opens another name");
    }
    if is_windows_device_name(name) {
        return Some(
            "is a Windows device name (CON, PRN, AUX, NUL, COM0-9, LPT0-9, CONIN$, CONOUT$)",
        );
    }
    // What this platform's own parser makes of it: on Windows this is where a rooted or
    // prefixed spelling the checks above missed would show; on Unix, after the checks
    // above, a segment is always one `Normal`.
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(only)), None) if only == name => None,
        _ => Some("is not one plain path segment on this platform"),
    }
}

/// Whether Windows reads `name` as a DOS device rather than a file: the part before the
/// first `.`, with trailing spaces dropped, is a reserved name in any case (`nul`,
/// `Com1.log`, `LPT¹`). `CONIN$` and `CONOUT$` are included, as current Windows treats them
/// the same way. The same list as ikigai-cli's (see [`windows_meaning`]).
fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = stem.to_uppercase();
    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        _ => ["COM", "LPT"].iter().any(|port| {
            upper.strip_prefix(port).is_some_and(|n| {
                matches!(
                    n,
                    "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        }),
    }
}

/// Kept identical in the aggregate description and the Sink action contract.
fn sink_encoding_arg() -> ArgSpec {
    ArgSpec::new("encoding")
        .summary("Sink only: encoding of content; defaults to utf-8.")
        .class(XSD_STRING)
        .one_of(["utf-8", "base64"])
        .optional()
        .default_value("utf-8")
}

/// How a Sink's `content` is encoded.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Utf8,
    Base64,
}

/// The Sink's `encoding`, judged before any content is read.
fn sink_encoding(inv: &Invocation<'_>) -> Result<Encoding> {
    if !inv.request.args.contains_key("encoding") {
        return Ok(Encoding::Utf8);
    }
    match inv.inline_str("encoding")? {
        "utf-8" => Ok(Encoding::Utf8),
        "base64" => Ok(Encoding::Base64),
        _ => Err(Error::InvalidArgument {
            name: "encoding".to_string(),
            detail: "expected utf-8 or base64".to_string(),
        }),
    }
}

fn not_utf8() -> Error {
    Error::InvalidArgument {
        name: "content".to_string(),
        detail: "not valid UTF-8".to_string(),
    }
}

fn not_base64() -> Error {
    Error::InvalidArgument {
        name: "content".to_string(),
        detail: "expected canonical standard-alphabet base64 with padding".to_string(),
    }
}

/// Content already in memory, decoded whole: the bytes to write.
fn decode_whole(encoding: Encoding, content: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>> {
    use base64::Engine as _;
    match encoding {
        Encoding::Utf8 => std::str::from_utf8(content)
            .map(|_| std::borrow::Cow::Borrowed(content))
            .map_err(|_| not_utf8()),
        Encoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(content)
            .map(std::borrow::Cow::Owned)
            .map_err(|_| not_base64()),
    }
}

/// Streamed content, decoded **incrementally**, chunk by chunk, holding at most
/// the few bytes a chunk boundary splits (a UTF-8 sequence, a base64 group): what
/// is written is exactly what [`decode_whole`] would have produced from the
/// whole, and anything [`decode_whole`] would refuse is refused, here or at
/// [`finish`](Self::finish).
#[cfg_attr(not(unix), allow(dead_code))]
struct Decoder {
    encoding: Encoding,
    /// The incomplete tail of the last chunk.
    carry: Vec<u8>,
    /// A padded base64 group was decoded: it must have been the last.
    ended: bool,
}

#[cfg_attr(not(unix), allow(dead_code))]
impl Decoder {
    fn new(encoding: Encoding) -> Self {
        Decoder {
            encoding,
            carry: Vec::new(),
            ended: false,
        }
    }

    /// Decode `chunk`, handing every complete decoded run to `out`.
    fn feed(&mut self, chunk: &[u8], out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        use base64::Engine as _;
        let joined;
        let data: &[u8] = if self.carry.is_empty() {
            chunk
        } else {
            joined = [self.carry.as_slice(), chunk].concat();
            &joined
        };
        let rest = match self.encoding {
            Encoding::Utf8 => {
                let valid = match std::str::from_utf8(data) {
                    Ok(_) => data.len(),
                    // `error_len() == None`: a sequence cut by the chunk's end.
                    Err(e) if e.error_len().is_none() => e.valid_up_to(),
                    Err(_) => return Err(not_utf8()),
                };
                out(&data[..valid])?;
                &data[valid..]
            }
            Encoding::Base64 => {
                if self.ended && !data.is_empty() {
                    return Err(not_base64());
                }
                let (groups, rest) = data.split_at(data.len() / 4 * 4);
                if !groups.is_empty() {
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(groups)
                        .map_err(|_| not_base64())?;
                    out(&decoded)?;
                    self.ended = groups.ends_with(b"=");
                    if self.ended && !rest.is_empty() {
                        return Err(not_base64());
                    }
                }
                rest
            }
        };
        self.carry = rest.to_vec();
        Ok(())
    }

    /// The content ended: refuse it if it ended inside a sequence or a group.
    fn finish(self) -> Result<()> {
        if self.carry.is_empty() {
            Ok(())
        } else if self.encoding == Encoding::Utf8 {
            Err(not_utf8())
        } else {
            Err(not_base64())
        }
    }
}

/// Write a Sink's `content` to the file the walk found, returning how many bytes
/// were written.
///
/// The content is read with [`Invocation::content_body`], so it may be inline, a
/// reference, or a content id. Content already in memory ([`Body::Bytes`]) is
/// decoded whole before the disk is touched, as before bodies existed. A stream is
/// decoded incrementally ([`Decoder`]) into the staging file chunk by chunk and
/// published only once it ended cleanly: a stream that fails part-way, content
/// that does not decode, or content past `max_write` (checked before each chunk
/// reaches the disk) leaves the target untouched and no staging file behind.
#[cfg(unix)]
async fn sink(
    inv: &Invocation<'_>,
    found: backend::Found,
    iri: &str,
    max_write: u64,
) -> Result<u64> {
    let encoding = sink_encoding(inv)?;
    let body = inv.content_body("content").await?;
    if let Body::Bytes(bytes) = &body {
        let content = decode_whole(encoding, bytes)?;
        within_max_write(content.len() as u64, max_write, iri)?;
        found.write(&content, iri)?;
        return Ok(content.len() as u64);
    }
    let mut stream = body.into_stream();
    let mut decoder = Decoder::new(encoding);
    let mut staged = found.stage(iri)?;
    let mut written = 0u64;
    while let Some(chunk) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
        decoder.feed(&chunk?, &mut |decoded| {
            written += decoded.len() as u64;
            within_max_write(written, max_write, iri)?;
            staged.write_all(decoded, iri)
        })?;
    }
    decoder.finish()?;
    staged.publish(iri)?;
    Ok(written)
}

/// The `localStorage` backend stores with one `set_item`, so `content` is collected
/// under the run's byte budget and decoded whole: what the kernel did for it before the
/// Sink declared `content` read as a body (ledger #2469), done here so both backends
/// keep one contract.
#[cfg(not(unix))]
async fn sink(
    inv: &Invocation<'_>,
    found: backend::Found,
    iri: &str,
    max_write: u64,
) -> Result<u64> {
    let encoding = sink_encoding(inv)?;
    let collected = inv.collect(inv.content_body("content").await?).await?;
    let content = decode_whole(encoding, &collected)?;
    within_max_write(content.len() as u64, max_write, iri)?;
    found.write(&content, iri)?;
    Ok(content.len() as u64)
}

/// Refuse a write that has reached `written` decoded bytes once that is past the root's
/// ceiling ([`FileEndpoint::max_write`]).
fn within_max_write(written: u64, max_write: u64, iri: &str) -> Result<()> {
    if written > max_write {
        return Err(Error::OverBudget {
            detail: format!(
                "{iri}: the write is past this root's {max_write}-byte ceiling \
                 (at least {written} bytes)"
            ),
        });
    }
    Ok(())
}

/// Whether a `Source` asks for raw bytes. `as` is declared `one_of
/// [application/octet-stream]`, and that is enforced here: this endpoint does not
/// convert, so any other value is refused rather than stamped onto bytes it does
/// not describe (a `.txt` upload relabeled `text/html` is an XSS on any HTTP edge).
/// The refusal shows the value `Debug`-escaped, so a control character in it never
/// reaches a header, a log line or a media type.
fn wants_raw_bytes(inv: &Invocation<'_>) -> Result<bool> {
    if !inv.request.args.contains_key("as") {
        return Ok(false);
    }
    let asked = inv.inline_str("as")?;
    if asked.eq_ignore_ascii_case(OCTET_STREAM) {
        return Ok(true);
    }
    Err(Error::InvalidArgument {
        name: "as".to_string(),
        detail: format!(
            "{asked:?} is not a face this endpoint serves: omit `as` for the file's own type, \
             or pass `{OCTET_STREAM}` for raw bytes"
        ),
    })
}

/// Whether `capability` grants `action` on the file at `names` (root-relative), by
/// the path-ACL.
///
/// `root` allows everything (the jail is the only remaining bound). Otherwise each
/// `urn:cap:fs:<action>:<path>` scope is mapped into the jail ([`Rule::map`]) and the
/// deepest rule that contains the target decides, with deny winning ties, and no
/// match meaning deny.
fn cap_allows(
    capability: &Capability,
    action: &str,
    root: &Path,
    jail: &backend::Jail,
    names: &[&str],
) -> bool {
    if capability.is_root() {
        return true;
    }
    let Some(scopes) = capability.scopes() else {
        return false;
    };
    let prefix = format!("urn:cap:fs:{action}:");
    let roots = Roots::of(root, jail);

    let mut best: Option<i64> = None;
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
        let Some(rule) = Rule::map(dir, rule_allows, &roots, jail) else {
            continue;
        };
        if !rule.contains(names) {
            continue;
        }
        let depth = rule.depth();
        match best {
            Some(b) if depth < b => {} // a more specific rule already decided
            Some(b) if depth == b => {
                // Tie on specificity: deny wins.
                allowed = allowed && rule_allows;
            }
            _ => {
                best = Some(depth);
                allowed = rule_allows;
            }
        }
    }
    best.is_some() && allowed
}

/// The jail root's spellings a scope may be written against: as mounted, and
/// canonical (every link resolved, absolute).
struct Roots {
    spellings: Vec<Vec<OsString>>,
    canonical: Option<Vec<OsString>>,
}

impl Roots {
    fn of(root: &Path, jail: &backend::Jail) -> Self {
        let mut spellings = Vec::new();
        if let Some(given) = lexical(root, true).filter(|c| !c.is_empty()) {
            spellings.push(given);
        }
        let canonical = jail
            .canonical_root()
            .and_then(|c| lexical(&c, true))
            .filter(|c| !c.is_empty());
        if let Some(canonical) = &canonical {
            if !spellings.contains(canonical) {
                spellings.push(canonical.clone());
            }
        }
        Roots {
            spellings,
            canonical,
        }
    }
}

/// One `urn:cap:fs:` rule, mapped into the jail.
enum Rule {
    /// The rule names the root itself or an ancestor of it, so it covers the whole
    /// jail; `0` for the root, `-n` for the n-th ancestor (less specific).
    Covers(i64),
    /// The rule names a path inside the jail: its names (on-disk for the first
    /// `on_disk`, as written past that), and whether it is a deny.
    Within {
        names: Vec<OsString>,
        on_disk: usize,
        deny: bool,
    },
}

impl Rule {
    /// Map a scope's path into the jail, or `None` when it names nothing in it.
    ///
    /// The path is normalized lexically first (so `/ws/secret/` and `/ws/secret` are
    /// one directory, of one depth). An allow containing `..` is ignored (fail
    /// closed); a deny's `..` is applied lexically. A deny that matches neither root
    /// spelling is tried once more with its existing prefix resolved through the
    /// host's links, so a deny spelled through a link to the jail still binds;
    /// allows get no such leniency.
    fn map(dir: &str, allows: bool, roots: &Roots, jail: &backend::Jail) -> Option<Rule> {
        let scope = lexical(Path::new(dir), !allows)?;
        let placed = roots
            .spellings
            .iter()
            .find_map(|root| place(&scope, root))
            .or_else(|| {
                if allows {
                    return None;
                }
                let resolved = backend::resolve_host_path(Path::new(dir))?;
                place(&lexical(&resolved, true)?, roots.canonical.as_deref()?)
            })?;
        Some(match placed {
            Placed::Covers(depth) => Rule::Covers(depth),
            Placed::Within(rest) if rest.is_empty() => Rule::Covers(0),
            Placed::Within(rest) => {
                let (names, on_disk) = jail.on_disk_names(&rest);
                Rule::Within {
                    names,
                    on_disk,
                    deny: !allows,
                }
            }
        })
    }

    fn depth(&self) -> i64 {
        match self {
            Rule::Covers(depth) => *depth,
            Rule::Within { names, .. } => names.len() as i64,
        }
    }

    /// Whether the rule's path is `target` itself or one of its ancestors,
    /// component-wise (so `a/b` does not contain `a/bc`).
    fn contains(&self, target: &[&str]) -> bool {
        match self {
            Rule::Covers(_) => true,
            Rule::Within {
                names,
                on_disk,
                deny,
            } => {
                names.len() <= target.len()
                    && names.iter().zip(target).enumerate().all(|(i, (rule, t))| {
                        if *deny && i >= *on_disk {
                            // A deny naming something not on disk: the volume's case
                            // rule for it is unknowable, so compare without case.
                            caseless_eq(rule, t)
                        } else {
                            rule.as_os_str() == OsStr::new(t)
                        }
                    })
            }
        }
    }
}

enum Placed {
    Covers(i64),
    Within(Vec<OsString>),
}

/// Place a normalized scope path against one spelling of the root.
fn place(scope: &[OsString], root: &[OsString]) -> Option<Placed> {
    if scope.starts_with(root) {
        Some(Placed::Within(scope[root.len()..].to_vec()))
    } else if root.starts_with(scope) {
        Some(Placed::Covers(-((root.len() - scope.len()) as i64)))
    } else {
        None
    }
}

/// A path's components with `.` and empty segments dropped, as comparable strings
/// (`/` stands for the root directory). `..` pops the previous name when
/// `resolve_parents`, and refuses the path otherwise (or when it would climb past the
/// start).
fn lexical(path: &Path, resolve_parents: bool) -> Option<Vec<OsString>> {
    let mut out: Vec<OsString> = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(p) => out.push(p.as_os_str().to_os_string()),
            Component::RootDir => out.push(OsString::from("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                if !resolve_parents {
                    return None;
                }
                match out.last() {
                    Some(last) if last != "/" => {
                        out.pop();
                    }
                    _ => return None,
                }
            }
            Component::Normal(name) => out.push(name.to_os_string()),
        }
    }
    Some(out)
}

fn caseless_eq(a: &OsStr, b: &str) -> bool {
    match a.to_str() {
        Some(a) => a == b || a.to_lowercase() == b.to_lowercase(),
        None => false,
    }
}

/// The representation type for a `Source`: raw bytes when asked, else the
/// extension-guessed type, else — "strings by default" — `text/plain` when the
/// bytes are valid UTF-8, else raw bytes.
fn source_type(name: &str, bytes: &[u8], raw: bool) -> ReprType {
    if raw {
        return ReprType::new(OCTET_STREAM);
    }
    let guessed = media_type_for(Path::new(name));
    if guessed.media_type != OCTET_STREAM {
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

/// A structural refusal of the `path` argument: permanent, and no capability
/// changes it.
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
        // A declared arrangement written as an s-expression (ikigai-sexpr's arrangement surface).
        // Deliberately NOT `text/x-sexpr`: ikigai-sexpr already has a lossless `text/x-sexpr →
        // text/turtle` transreptor (the code-graph profile), so a lossless-only selector over that
        // type would hand the arrangement builder a list graph instead of an arrangement.
        Some("arrangement") => "text/x-ikigai-arrangement",
        _ => OCTET_STREAM,
    };
    ReprType::new(media)
}

// --- platform backend ------------------------------------------------------
//
// Each backend provides the same surface: a `Jail` (the opened root), a `Found`
// (what a walk of the request's names reached), and the four operations on it.
// The lexical rules and the capability ACL above are platform-agnostic.

/// Native backend (Unix): every name is resolved with `openat` relative to a handle
/// on its parent, never following a link, and the operation happens on the handle
/// the walk produced.
#[cfg(unix)]
mod backend {
    use super::*;
    use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags};
    use rustix::io::Errno;
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    /// The jail's anchor: an open handle on the root, taken for this request.
    pub(super) struct Jail {
        root: OwnedFd,
        canonical: Option<PathBuf>,
    }

    impl Jail {
        /// Open the root, following links in the root's own path (host
        /// configuration, not caller input). Fails closed: a root that cannot be
        /// opened serves nothing, and is never created.
        pub(super) fn open(root: &Path, iri: &str) -> Result<Jail> {
            let fd = rfs::open(
                root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| {
                Error::Endpoint(format!(
                    "`{iri}`: the endpoint's jail root cannot be opened ({e}); nothing is \
                     served until it exists"
                ))
            })?;
            Ok(Jail {
                root: fd,
                canonical: std::fs::canonicalize(root).ok(),
            })
        }

        pub(super) fn canonical_root(&self) -> Option<PathBuf> {
            self.canonical.clone()
        }

        /// A scope's in-jail names resolved to their on-disk spelling, as far as they
        /// exist (without following links); past that, as written. Returns the names
        /// and how many of them are on disk.
        pub(super) fn on_disk_names(&self, rest: &[OsString]) -> (Vec<OsString>, usize) {
            let mut out: Vec<OsString> = Vec::new();
            let mut dir: Option<OwnedFd> = None;
            for (i, name) in rest.iter().enumerate() {
                let parent = dir.as_ref().unwrap_or(&self.root);
                let Ok(stat) = rfs::statat(parent, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
                else {
                    break;
                };
                if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink {
                    break;
                }
                let Ok(Some(real)) = disk_name(parent, name.as_os_str(), stat.st_ino) else {
                    break;
                };
                out.push(real);
                if i + 1 < rest.len() {
                    match open_dir(parent, name.as_os_str()) {
                        Ok(child) => dir = Some(child),
                        Err(_) => break,
                    }
                }
            }
            let on_disk = out.len();
            out.extend(rest[on_disk..].iter().cloned());
            (out, on_disk)
        }

        /// Walk `names` from the root without following a link and without creating
        /// anything. Refuses a link anywhere and a spelling that is not the on-disk
        /// one; stops quietly at the first name that does not exist.
        pub(super) fn probe(self, names: &[&str], iri: &str) -> Result<Found> {
            let (leaf, dirs) = names.split_last().expect("canonical_names is non-empty");
            let mut dir = self.root;
            for (reached, name) in dirs.iter().enumerate() {
                match step(&dir, name, &names[..=reached], iri)? {
                    Step::Dir(child) => dir = child,
                    Step::Missing => return Ok(Found::short(dir, names, reached, false)),
                    Step::NotDir => return Ok(Found::short(dir, names, reached, true)),
                }
            }
            let leaf_stat = match rfs::statat(&dir, *leaf, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => {
                    if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink {
                        return Err(link_refused(names));
                    }
                    check_spelling(&dir, leaf, stat.st_ino, names)?;
                    Some(stat)
                }
                Err(Errno::NOENT) => None,
                Err(e) => return Err(io_error("look up", iri, e)),
            };
            Ok(Found {
                dir,
                names: names.iter().map(|n| n.to_string()).collect(),
                reached: dirs.len(),
                blocked: false,
                leaf: leaf_stat,
            })
        }
    }

    /// What a walk reached: a handle on the deepest existing directory of the path
    /// (the leaf's parent when every directory exists) and the leaf's metadata.
    pub(super) struct Found {
        dir: OwnedFd,
        names: Vec<String>,
        /// How many of the path's directories exist; `dir` is the last of them.
        reached: usize,
        /// The walk stopped at a FILE where a directory was named.
        blocked: bool,
        leaf: Option<rfs::Stat>,
    }

    impl Found {
        fn short(dir: OwnedFd, names: &[&str], reached: usize, blocked: bool) -> Found {
            Found {
                dir,
                names: names.iter().map(|n| n.to_string()).collect(),
                reached,
                blocked,
                leaf: None,
            }
        }

        fn leaf_name(&self) -> &str {
            self.names.last().expect("non-empty")
        }

        fn shown(&self) -> String {
            self.names.join("/")
        }

        pub(super) fn exists(&self) -> bool {
            self.leaf.is_some()
        }

        pub(super) fn read(self, iri: &str) -> Result<Vec<u8>> {
            let (fd, now) = self.open_judged(iri)?;
            read_bounded(std::fs::File::from(fd), now.st_size, iri)
        }

        /// Open the leaf the walk judged, through the walk's parent handle and
        /// without following a link, and confirm it is still that file.
        fn open_judged(&self, iri: &str) -> Result<(OwnedFd, rfs::Stat)> {
            let Some(stat) = self.leaf.as_ref() else {
                return Err(not_found(iri));
            };
            require_regular(stat, &self.shown())?;
            let fd = open_leaf(&self.dir, self.leaf_name(), &self.shown(), iri)?;
            // The handle is the file judged: the same inode the walk found, still a
            // regular file. Anything else was swapped in since.
            let now = rfs::fstat(&fd).map_err(|e| io_error("read", iri, e))?;
            if now.st_ino != stat.st_ino || now.st_dev != stat.st_dev {
                return Err(changed(iri));
            }
            require_regular(&now, &self.shown())?;
            Ok((fd, now))
        }

        /// A `Source` as a body: a [`FileReplay`] over the file the walk judged,
        /// its version (size, inode, mtime, ctime) recorded now. The media type
        /// follows [`source_type`]'s rules; where they need the bytes (no `as`, an
        /// extension with no known type), a file within [`MAX_FILE_SOURCE_BYTES`]
        /// is checked for UTF-8 by one bounded-chunk pass that holds no more than a
        /// chunk, and a larger one is served as bytes.
        pub(super) fn body(self, leaf: &str, raw: bool, iri: &str) -> Result<(ReprType, Body)> {
            let (fd, at_open) = self.open_judged(iri)?;
            let guessed = media_type_for(Path::new(leaf));
            let repr_type = if raw {
                ReprType::new(OCTET_STREAM)
            } else if guessed.media_type != OCTET_STREAM
                || at_open.st_size > MAX_FILE_SOURCE_BYTES as i64
            {
                guessed
            } else if is_utf8(FileReader::new(fd, at_open, 0, iri))? {
                ReprType::new("text/plain").with_param("charset", "utf-8")
            } else {
                guessed
            };
            let replay = FileReplay {
                leaf: self.leaf_name().to_string(),
                shown: self.shown(),
                iri: iri.to_string(),
                at_open,
                dir: self.dir,
                validator: std::sync::OnceLock::new(),
            };
            Ok((repr_type, Body::replay(replay)))
        }

        pub(super) fn write(self, bytes: &[u8], iri: &str) -> Result<()> {
            self.write_with(iri, |file| file.write_all(bytes))
        }

        // Keep the actual I/O injectable so tests can stop after a short write or
        // return an I/O error at exactly that point, without process-wide hooks.
        pub(super) fn write_with(
            self,
            iri: &str,
            write: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
        ) -> Result<()> {
            let mut pending = self.stage(iri)?;
            write(&mut pending.staged.file)
                .map_err(|e| Error::Endpoint(format!("write `{iri}`: {e}")))?;
            pending.publish(iri)
        }

        /// Prepare a write: create the missing directories, hold the old file, and
        /// exclusively create a staging file in the opened parent. Nothing is
        /// visible at the target until [`Pending::publish`]; dropping the
        /// [`Pending`] instead removes the staging file and leaves the target as it
        /// was.
        pub(super) fn stage(self, iri: &str) -> Result<Pending> {
            let shown = self.shown();
            if self.blocked {
                return Err(deny(&format!(
                    "`{}` is a file, not a directory",
                    self.names[..=self.reached].join("/")
                )));
            }
            if let Some(stat) = &self.leaf {
                require_regular(stat, &shown)?;
            }
            // Create the missing directories, each relative to the handle on its
            // parent, and descend into each through a fresh no-follow open — so a
            // name swapped for a link meanwhile is refused, never followed.
            let mut dir = self.dir;
            let all: Vec<&str> = self.names.iter().map(String::as_str).collect();
            let dirs = &all[..all.len() - 1];
            for (i, name) in dirs.iter().copied().enumerate().skip(self.reached) {
                match rfs::mkdirat(&dir, name, Mode::from_raw_mode(0o777)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(e) => return Err(io_error("create a directory for", iri, e)),
                }
                match step(&dir, name, &all[..=i], iri)? {
                    Step::Dir(child) => dir = child,
                    Step::Missing => return Err(changed(iri)),
                    Step::NotDir => {
                        return Err(deny(&format!(
                            "`{}` is a file, not a directory",
                            all[..=i].join("/")
                        )))
                    }
                }
            }
            let leaf = *all.last().expect("non-empty");
            // Retain the old handle until publication, checking the same inode the
            // probe judged and enforcing the existing file's write permissions.
            let old = if let Some(expected) = &self.leaf {
                let fd = rfs::openat(
                    &dir,
                    leaf,
                    OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .map_err(|e| match e {
                    Errno::LOOP | Errno::MLINK => link_refused_shown(&shown),
                    Errno::NOENT => changed(iri),
                    e => io_error("write", iri, e),
                })?;
                let now = rfs::fstat(&fd).map_err(|e| io_error("write", iri, e))?;
                require_regular(&now, &shown)?;
                if now.st_ino != expected.st_ino || now.st_dev != expected.st_dev {
                    return Err(changed(iri));
                }
                Some(fd)
            } else {
                None
            };

            let mode = Mode::from_raw_mode(if self.leaf.is_some() { 0o600 } else { 0o666 });
            let staged = Staged::create(dir, mode, iri)?;
            Ok(Pending {
                staged,
                leaf: leaf.to_string(),
                names: self.names,
                expected: self.leaf,
                old,
            })
        }
    }

    /// A staged write ([`Found::stage`]): the staging file, open for writing, and
    /// what publication checks before it makes the file visible.
    pub(super) struct Pending {
        staged: Staged,
        leaf: String,
        names: Vec<String>,
        /// The file the walk judged, when one was there.
        expected: Option<rfs::Stat>,
        /// A handle on that file, held until publication.
        old: Option<OwnedFd>,
    }

    impl Pending {
        /// Append `bytes` to the staging file.
        pub(super) fn write_all(&mut self, bytes: &[u8], iri: &str) -> Result<()> {
            self.staged
                .file
                .write_all(bytes)
                .map_err(|e| Error::Endpoint(format!("write `{iri}`: {e}")))
        }

        /// Sync the staging file and publish it at the target: `renameat` over an
        /// existing file (an open reader keeps the old inode and its bytes), or
        /// `linkat` for a new one (never overwriting a name that appeared since).
        pub(super) fn publish(self, iri: &str) -> Result<()> {
            let Pending {
                staged,
                leaf,
                names,
                expected,
                old,
            } = self;
            let shown = names.join("/");
            let all: Vec<&str> = names.iter().map(String::as_str).collect();
            let leaf = leaf.as_str();
            let dir = &staged.dir;
            // Preserve ordinary permission bits on replacement, without carrying
            // set-id bits onto new content. New files retain 0666 filtered by umask.
            if let Some(expected) = &expected {
                rfs::fchmod(&staged.file, Mode::from_raw_mode(expected.st_mode & 0o777))
                    .map_err(|e| io_error("set permissions for", iri, e))?;
            }
            staged
                .file
                .sync_all()
                .map_err(|e| Error::Endpoint(format!("sync `{iri}`: {e}")))?;

            // The temporary name must still refer to the regular inode written
            // through our handle, rather than an entry substituted during I/O.
            let staged_stat = rfs::fstat(&staged.file).map_err(|e| io_error("publish", iri, e))?;
            let named_stat = rfs::statat(dir, staged.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| io_error("publish", iri, e))?;
            require_regular(&named_stat, &shown)?;
            if staged_stat.st_ino != named_stat.st_ino || staged_stat.st_dev != named_stat.st_dev {
                return Err(changed(iri));
            }

            if let Some(expected) = &expected {
                // Revalidate after staging: a new inode or symlink planted while
                // bytes were being written must not be adopted by this request.
                let now = rfs::statat(dir, leaf, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|e| io_error("write", iri, e))?;
                require_regular(&now, &shown)?;
                if now.st_ino != expected.st_ino || now.st_dev != expected.st_dev {
                    return Err(changed(iri));
                }
                check_spelling(dir, leaf, now.st_ino, &all)?;
                rfs::renameat(dir, staged.name.as_str(), dir, leaf)
                    .map_err(|e| io_error("publish", iri, e))?;
            } else {
                // Portable exclusive publication: link a complete file into place.
                // Unlike rename, linkat cannot overwrite a name that appeared
                // since the probe. Drop removes only the temporary second name.
                rfs::linkat(dir, staged.name.as_str(), dir, leaf, AtFlags::empty()).map_err(
                    |e| match e {
                        Errno::EXIST => changed(iri),
                        e => io_error("publish", iri, e),
                    },
                )?;
            }
            drop(old);
            Ok(())
        }
    }

    impl Found {
        pub(super) fn delete(self, iri: &str) -> Result<()> {
            let Some(stat) = &self.leaf else {
                return Err(not_found(iri));
            };
            if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
                return Err(deny(&format!(
                    "`{}` is a directory; this endpoint deletes files",
                    self.shown()
                )));
            }
            // `unlinkat` never follows a link: it removes the name the ACL judged.
            rfs::unlinkat(&self.dir, self.leaf_name(), AtFlags::empty()).map_err(|e| match e {
                Errno::NOENT => not_found(iri),
                e => io_error("delete", iri, e),
            })
        }
    }

    /// The largest chunk a [`FileReplay`] reader yields.
    const CHUNK: u64 = 64 * 1024;

    /// A file `Source` as a [`Replay`](ikigai_core::Replay) (ledger #2245).
    ///
    /// It holds the handle on the leaf's parent that the jailed walk opened, and
    /// the file's version at open. Every reader opens a fresh descriptor for the
    /// leaf through that handle without following a link — never a host path that
    /// re-walks the jail — and is refused unless it is the same file, unchanged.
    /// It reads chunks of at most [`CHUNK`] bytes, each poll one bounded blocking
    /// read on the polling thread, as the crate does all of its file I/O; and at
    /// the end it checks the version again ([`same_version`]). **A file changed
    /// while read** (size, inode, mtime or ctime moved; a write in place, a
    /// replacement since the body was opened) **ends the stream with
    /// [`Error::Conflict`]**, never a short or
    /// mixed body. A reader already open when a `Sink` replaces the file keeps the
    /// old inode, so it reads the old bytes whole.
    ///
    /// Its [`validator`](ikigai_core::Replay::validator) is the content id of the
    /// version at open, hashed by one such reader the first time it is asked for
    /// and remembered ([`validators`]); see [`VALIDATOR_SETTLE`].
    ///
    /// A cached body (a [`cacheable`](super::FileEndpoint::cacheable) mount) keeps
    /// its parent handle open until the cache lets it go.
    struct FileReplay {
        dir: OwnedFd,
        leaf: String,
        shown: String,
        iri: String,
        at_open: rfs::Stat,
        validator: std::sync::OnceLock<ikigai_core::ContentId>,
    }

    impl FileReplay {
        fn reader(&self, offset: u64) -> FileReader {
            let fresh = open_leaf(&self.dir, &self.leaf, &self.shown, &self.iri).and_then(|fd| {
                let now = rfs::fstat(&fd).map_err(|e| io_error("read", &self.iri, e))?;
                if same_version(&now, &self.at_open) {
                    Ok(fd)
                } else {
                    Err(changed_while_read(&self.iri))
                }
            });
            match fresh {
                Ok(fd) => FileReader::new(fd, self.at_open, offset, &self.iri),
                Err(Error::NotFound(_)) => FileReader::failed(changed_while_read(&self.iri)),
                Err(e) => FileReader::failed(e),
            }
        }
    }

    impl ikigai_core::Replay for FileReplay {
        fn open(&self) -> ikigai_core::ByteStream {
            Box::pin(self.reader(0))
        }

        /// A reader from byte `offset`; past the end it yields nothing (still
        /// checked for a change at its end).
        fn open_at(&self, offset: u64) -> Option<ikigai_core::ByteStream> {
            Some(Box::pin(self.reader(offset)))
        }

        fn len_hint(&self) -> Option<u64> {
            u64::try_from(self.at_open.st_size).ok()
        }

        /// The content id of the version at open (ledger #2474). Strong by
        /// construction (RFC 9110 §8.8.1): it is the digest of exactly the bytes a
        /// reader of this body serves, hashed by such a reader, so it fails, and
        /// nothing is stated, if the file changed while hashed. Remembered against
        /// the version, the only cost is the first full read of each version. `None`
        /// while the file's last change is younger than [`VALIDATOR_SETTLE`], or when
        /// the read fails.
        fn validator(&self) -> Option<ikigai_core::ContentId> {
            if let Some(id) = self.validator.get() {
                return Some(*id);
            }
            let changed = std::time::UNIX_EPOCH.checked_add(std::time::Duration::new(
                u64::try_from(self.at_open.st_ctime).ok()?,
                u32::try_from(self.at_open.st_ctime_nsec).ok()?,
            ))?;
            // Settled measured before the read, so the bytes hashed are no older than
            // a version that had already stood for the whole window.
            let settled = std::time::SystemTime::now()
                .duration_since(changed)
                .is_ok_and(|age| age >= VALIDATOR_SETTLE);
            if !settled {
                return None;
            }
            let key = Version::of(&self.at_open);
            let known = validators().lock().ok()?.get(&key).copied();
            let id = match known {
                Some(id) => id,
                None => {
                    let id = digest(self.reader(0)).ok()?;
                    let mut held = validators().lock().ok()?;
                    if held.len() >= MAX_VALIDATORS {
                        held.clear();
                    }
                    held.insert(key, id);
                    id
                }
            };
            Some(*self.validator.get_or_init(|| id))
        }
    }

    /// How many file versions' digests [`validators`] remembers; past it they are
    /// forgotten together, and hashed again when next asked for.
    const MAX_VALIDATORS: usize = 4096;

    /// A file's version as [`validators`] keys it: every stamp a change to its
    /// bytes moves. ctime is the one a writer cannot set back.
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    struct Version {
        dev: u64,
        ino: u64,
        size: i64,
        mtime: (i64, i64),
        ctime: (i64, i64),
    }

    impl Version {
        #[allow(clippy::unnecessary_cast)] // the stat fields' widths vary by target
        fn of(stat: &rfs::Stat) -> Self {
            Version {
                dev: stat.st_dev as u64,
                ino: stat.st_ino as u64,
                size: stat.st_size as i64,
                mtime: (stat.st_mtime as i64, stat.st_mtime_nsec as i64),
                ctime: (stat.st_ctime as i64, stat.st_ctime_nsec as i64),
            }
        }
    }

    /// The content ids of the file versions hashed so far, process-wide: a second
    /// body over an unchanged file, or a second mount of it, states its validator
    /// without reading it again. Only settled versions ([`VALIDATOR_SETTLE`]) are
    /// entered, so a reused inode is a new ctime and never finds an old digest.
    fn validators(
    ) -> &'static std::sync::Mutex<std::collections::HashMap<Version, ikigai_core::ContentId>> {
        static HELD: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<Version, ikigai_core::ContentId>>,
        > = std::sync::OnceLock::new();
        HELD.get_or_init(Default::default)
    }

    /// The content id of everything `reader` reads; its error (a change while read
    /// is [`Error::Conflict`]) when the read fails.
    fn digest(mut reader: FileReader) -> Result<ikigai_core::ContentId> {
        let mut hasher = ikigai_core::ContentHasher::new();
        while let Some(chunk) = reader.next_chunk() {
            hasher.update(&chunk?);
        }
        Ok(hasher.finish())
    }

    /// One reader of a [`FileReplay`]: a fresh descriptor, how many bytes the
    /// version at open leaves to read, and that version to check at the end.
    struct FileReader {
        /// The descriptor and the version it must still be at its end; `None`
        /// once the stream ended.
        file: Option<(std::fs::File, rfs::Stat)>,
        remaining: u64,
        iri: String,
        failed: Option<Error>,
    }

    impl FileReader {
        fn new(fd: OwnedFd, expected: rfs::Stat, offset: u64, iri: &str) -> Self {
            use std::io::{Seek, SeekFrom};
            let size = u64::try_from(expected.st_size).unwrap_or(0);
            let mut file = std::fs::File::from(fd);
            let mut reader = FileReader {
                file: None,
                remaining: size.saturating_sub(offset),
                iri: iri.to_string(),
                failed: None,
            };
            match file.seek(SeekFrom::Start(offset)) {
                Ok(_) => reader.file = Some((file, expected)),
                Err(e) => reader.failed = Some(Error::Endpoint(format!("read `{iri}`: {e}"))),
            }
            reader
        }

        fn failed(error: Error) -> Self {
            FileReader {
                file: None,
                remaining: 0,
                iri: String::new(),
                failed: Some(error),
            }
        }

        /// The next chunk, the error that ends the stream, or `None` at a clean end.
        fn next_chunk(&mut self) -> Option<Result<ikigai_core::Bytes>> {
            if let Some(error) = self.failed.take() {
                return Some(Err(error));
            }
            let (file, expected) = self.file.as_mut()?;
            // One byte past what is left, so growth shows without a second read.
            let mut buf = vec![0u8; (self.remaining.min(CHUNK - 1) + 1) as usize];
            let read = loop {
                match file.read(&mut buf) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    other => break other,
                }
            };
            match read {
                Ok(0) => {
                    let unchanged = self.remaining == 0
                        && rfs::fstat(&*file).is_ok_and(|now| same_version(&now, expected));
                    self.file = None;
                    (!unchanged).then(|| Err(changed_while_read(&self.iri)))
                }
                Ok(n) if n as u64 > self.remaining => {
                    self.file = None;
                    Some(Err(changed_while_read(&self.iri)))
                }
                Ok(n) => {
                    self.remaining -= n as u64;
                    buf.truncate(n);
                    Some(Ok(buf.into()))
                }
                Err(e) => {
                    self.file = None;
                    Some(Err(Error::Endpoint(format!("read `{}`: {e}", self.iri))))
                }
            }
        }
    }

    impl futures_core::Stream for FileReader {
        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(self.get_mut().next_chunk())
        }

        type Item = Result<ikigai_core::Bytes>;
    }

    /// Whether the file a reader reads is valid UTF-8, read once in bounded
    /// chunks. A change while read is the reader's [`Error::Conflict`].
    fn is_utf8(mut reader: FileReader) -> Result<bool> {
        let mut decoder = Decoder::new(Encoding::Utf8);
        while let Some(chunk) = reader.next_chunk() {
            if decoder.feed(&chunk?, &mut |_| Ok(())).is_err() {
                return Ok(false);
            }
        }
        Ok(decoder.finish().is_ok())
    }

    /// Whether two stats are one version of one file: same inode, size and mtime,
    /// and same ctime unless the link count moved. A write moves mtime and ctime;
    /// resetting mtime afterwards moves ctime again. A link count that changed
    /// (a `Sink` renaming a new file over this one, a hard link made) moves ctime
    /// without touching the bytes, so an open reader of a replaced file still
    /// reads its old bytes whole.
    fn same_version(a: &rfs::Stat, b: &rfs::Stat) -> bool {
        a.st_dev == b.st_dev
            && a.st_ino == b.st_ino
            && a.st_size == b.st_size
            && a.st_mtime == b.st_mtime
            && a.st_mtime_nsec == b.st_mtime_nsec
            && (a.st_nlink != b.st_nlink
                || (a.st_ctime == b.st_ctime && a.st_ctime_nsec == b.st_ctime_nsec))
    }

    /// Open the leaf `name` in the walk's directory `dir` for reading, never
    /// following a link.
    fn open_leaf(dir: &OwnedFd, name: &str, shown: &str, iri: &str) -> Result<OwnedFd> {
        rfs::openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|e| match e {
            Errno::LOOP | Errno::MLINK => link_refused_shown(shown),
            e => io_error("read", iri, e),
        })
    }

    /// A staging file in the *opened* parent, never a host path that re-walks
    /// the jail. Exclusive creation refuses collisions and Drop cleans every
    /// ordinary error path (a killed process can leave an unpublished orphan).
    struct Staged {
        dir: OwnedFd,
        name: String,
        file: std::fs::File,
    }

    impl Staged {
        fn create(dir: OwnedFd, mode: Mode, iri: &str) -> Result<Self> {
            for _ in 0..16 {
                let mut random = [0u8; 16];
                getrandom::fill(&mut random).map_err(|_| {
                    Error::Endpoint(format!("stage `{iri}`: randomness unavailable"))
                })?;
                let name = format!(".ikigai-fs-{:032x}.tmp", u128::from_ne_bytes(random));
                match rfs::openat(
                    &dir,
                    name.as_str(),
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    mode,
                ) {
                    Ok(fd) => {
                        return Ok(Self {
                            dir,
                            name,
                            file: fd.into(),
                        })
                    }
                    Err(Errno::EXIST) => continue,
                    Err(e) => return Err(io_error("stage", iri, e)),
                }
            }
            Err(Error::Endpoint(format!(
                "stage `{iri}`: temporary name collisions"
            )))
        }
    }

    impl Drop for Staged {
        fn drop(&mut self) {
            let _ = rfs::unlinkat(&self.dir, self.name.as_str(), AtFlags::empty());
        }
    }

    /// Metadata rejects known oversize files without reading; the extra byte
    /// detects growth (or a file whose reported size understates its contents).
    pub(super) fn read_bounded(reader: impl Read, size: i64, iri: &str) -> Result<Vec<u8>> {
        let over_budget = || Error::OverBudget {
            detail: format!(
                "read `{iri}` exceeds the {MAX_FILE_SOURCE_BYTES}-byte file Source limit"
            ),
        };
        if size > MAX_FILE_SOURCE_BYTES as i64 {
            return Err(over_budget());
        }
        let mut bytes = Vec::new();
        reader
            .take(MAX_FILE_SOURCE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Endpoint(format!("read `{iri}`: {e}")))?;
        if bytes.len() as u64 > MAX_FILE_SOURCE_BYTES {
            return Err(over_budget());
        }
        Ok(bytes)
    }

    enum Step {
        Dir(OwnedFd),
        Missing,
        NotDir,
    }

    /// Descend one directory name from `dir`: no link followed, on-disk spelling
    /// required.
    fn step(dir: &OwnedFd, name: &str, so_far: &[&str], iri: &str) -> Result<Step> {
        match open_dir(dir, OsStr::new(name)) {
            Ok(child) => {
                let stat = rfs::fstat(&child).map_err(|e| io_error("look up", iri, e))?;
                check_spelling(dir, name, stat.st_ino, so_far)?;
                Ok(Step::Dir(child))
            }
            Err(Errno::NOENT) => Ok(Step::Missing),
            // The open refused: say why from the name itself (a link, a file),
            // since `O_NOFOLLOW | O_DIRECTORY` on a link is ELOOP on some systems,
            // ENOTDIR or EMLINK on others.
            Err(e) => match rfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink => {
                    Err(link_refused(so_far))
                }
                Ok(stat) if FileType::from_raw_mode(stat.st_mode) != FileType::Directory => {
                    Ok(Step::NotDir)
                }
                Err(Errno::NOENT) => Ok(Step::Missing),
                _ => Err(io_error("look up", iri, e)),
            },
        }
    }

    fn open_dir(dir: &OwnedFd, name: &OsStr) -> rustix::io::Result<OwnedFd> {
        rfs::openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    }

    /// The on-disk spelling of the entry `name` opened in `dir`: `name` itself when an
    /// entry is spelled exactly so, else the entry with the opened inode (the name a
    /// case- or normalization-folding volume matched). `None` if neither is listed.
    fn disk_name(dir: &OwnedFd, name: &OsStr, ino: u64) -> rustix::io::Result<Option<OsString>> {
        let mut by_inode = None;
        for entry in rfs::Dir::read_from(dir.as_fd())? {
            let entry = entry?;
            let listed = OsStr::from_bytes(entry.file_name().to_bytes());
            if listed == name {
                return Ok(Some(name.to_os_string()));
            }
            if by_inode.is_none() && entry.ino() == ino && listed != "." && listed != ".." {
                by_inode = Some(listed.to_os_string());
            }
        }
        Ok(by_inode)
    }

    /// Refuse a name that reached a file under a spelling other than its own — the
    /// alias a case-insensitive volume makes of `NOTES.txt` for `notes.txt`.
    ///
    /// Confirming a spelling needs the parent LISTED, not only traversed: a directory
    /// the host lets us search but not read is reported as such, never as a spelling
    /// error.
    fn check_spelling(dir: &OwnedFd, name: &str, ino: u64, so_far: &[&str]) -> Result<()> {
        match disk_name(dir, OsStr::new(name), ino) {
            Ok(Some(real)) if real == OsStr::new(name) => Ok(()),
            Err(e) => Err(Error::Endpoint(format!(
                "`{}`: its directory cannot be listed to confirm the name's spelling ({e})",
                so_far.join("/")
            ))),
            Ok(_) => Err(deny(&format!(
                "`{}` is not the on-disk spelling of that name (the volume folds case or \
                 normalization); name the file exactly as it is spelled on disk",
                so_far.join("/")
            ))),
        }
    }

    fn require_regular(stat: &rfs::Stat, shown: &str) -> Result<()> {
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => Ok(()),
            FileType::Directory => Err(deny(&format!("`{shown}` is a directory, not a file"))),
            _ => Err(deny(&format!("`{shown}` is not a regular file"))),
        }
    }

    fn link_refused(so_far: &[&str]) -> Error {
        link_refused_shown(&so_far.join("/"))
    }

    fn link_refused_shown(shown: &str) -> Error {
        deny(&format!(
            "`{shown}` is a symbolic link; this endpoint never follows links"
        ))
    }

    fn not_found(iri: &str) -> Error {
        Error::NotFound(format!("`{iri}` does not exist"))
    }

    /// A body's file changed between its open and a reader's end (the
    /// [`Replay`](ikigai_core::Replay) contract).
    fn changed_while_read(iri: &str) -> Error {
        Error::Conflict(format!("`{iri}` changed while read; read it again"))
    }

    fn changed(iri: &str) -> Error {
        Error::Endpoint(format!(
            "`{iri}` changed on disk while the request was being served; retry"
        ))
    }

    /// An OS failure, naming the request's IRI and never the host path (an `Errno`
    /// carries no path).
    fn io_error(op: &str, iri: &str, e: Errno) -> Error {
        match e {
            Errno::NOENT => not_found(iri),
            e => Error::Endpoint(format!("{op} `{iri}`: {e}")),
        }
    }

    /// A host path with its existing prefix resolved through links (the rest kept as
    /// written). Used only to place a DENY scope spelled through a link to the jail.
    pub(super) fn resolve_host_path(path: &Path) -> Option<PathBuf> {
        if !path.is_absolute() {
            return None;
        }
        let mut existing = path;
        let mut tail: Vec<&OsStr> = Vec::new();
        loop {
            if let Ok(real) = std::fs::canonicalize(existing) {
                let mut out = real;
                out.extend(tail.iter().rev());
                return Some(out);
            }
            tail.push(existing.file_name()?);
            existing = existing.parent()?;
        }
    }

    #[cfg(test)]
    pub(super) fn probe_for_test(root: &Path, names: &[&str]) -> Result<Found> {
        Jail::open(root, "urn:file:test")?.probe(names, "urn:file:test")
    }
}

/// wasm32 backend: the browser's `localStorage`, with the jailed target path
/// mapped to a namespaced key (`ikigai:fs:<root>/<path>`) so several mounts/roots
/// coexist in one origin's store. `localStorage` has no links and no case folding,
/// so a key has one spelling and the lexical rules are the whole jail.
///
/// New writes store base64 in a separate `ikigai:fs-bytes:` namespace. Reads
/// prefer that entry, falling back to the original text key for existing stores.
/// Separate keys avoid interpreting any legacy text as a binary format marker;
/// the encoding is internal and Source still returns the stored bytes.
///
/// It installs no spill facility: there is no file system to spill to, so a browser
/// host's `urn:stream:spill` answers `Unsupported` (the file-backed `FileSpill` is
/// Unix only).
#[cfg(target_family = "wasm")]
mod backend {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    pub(super) struct Jail {
        root: PathBuf,
    }

    /// This origin's `localStorage`, or an error if it isn't available (no window,
    /// or storage disabled).
    fn storage(iri: &str) -> Result<web_sys::Storage> {
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .ok_or_else(|| {
                Error::Endpoint(format!(
                    "`{iri}`: localStorage is unavailable in this context"
                ))
            })
    }

    impl Jail {
        pub(super) fn open(root: &Path, _iri: &str) -> Result<Jail> {
            Ok(Jail {
                root: root.to_path_buf(),
            })
        }

        pub(super) fn canonical_root(&self) -> Option<PathBuf> {
            None
        }

        pub(super) fn on_disk_names(&self, rest: &[OsString]) -> (Vec<OsString>, usize) {
            (rest.to_vec(), rest.len())
        }

        pub(super) fn probe(self, names: &[&str], iri: &str) -> Result<Found> {
            // The same key the pre-0.1.8 backend used for a canonical spelling.
            let key = format!("ikigai:fs:{}", self.root.join(names.join("/")).display());
            let bytes_key = format!(
                "ikigai:fs-bytes:{}",
                self.root.join(names.join("/")).display()
            );
            let store = storage(iri)?;
            let present = store
                .get_item(&bytes_key)
                .map_err(|_| Error::Endpoint(format!("exists `{iri}`: localStorage error")))?
                .or(store
                    .get_item(&key)
                    .map_err(|_| Error::Endpoint(format!("exists `{iri}`: localStorage error")))?)
                .is_some();
            Ok(Found {
                key,
                bytes_key,
                present,
            })
        }
    }

    pub(super) struct Found {
        key: String,
        bytes_key: String,
        present: bool,
    }

    impl Found {
        pub(super) fn exists(&self) -> bool {
            self.present
        }

        pub(super) fn read(self, iri: &str) -> Result<Vec<u8>> {
            let store = storage(iri)?;
            if let Some(encoded) = store
                .get_item(&self.bytes_key)
                .map_err(|_| Error::Endpoint(format!("read `{iri}`: localStorage error")))?
            {
                return STANDARD.decode(encoded).map_err(|_| {
                    Error::Endpoint(format!("read `{iri}`: corrupt base64 in localStorage"))
                });
            }
            let value = store
                .get_item(&self.key)
                .map_err(|_| Error::Endpoint(format!("read `{iri}`: localStorage error")))?;
            match value {
                Some(text) => Ok(text.into_bytes()),
                None => Err(Error::NotFound(format!("`{iri}` does not exist"))),
            }
        }

        pub(super) fn write(self, bytes: &[u8], iri: &str) -> Result<()> {
            // One set_item atomically replaces the complete file, even when quota
            // exhaustion refuses a write. Legacy text remains a read-only fallback.
            storage(iri)?
                .set_item(&self.bytes_key, &STANDARD.encode(bytes))
                .map_err(|_| Error::Endpoint(format!("write `{iri}`: localStorage error (quota?)")))
        }

        pub(super) fn delete(self, iri: &str) -> Result<()> {
            if !self.present {
                return Err(Error::NotFound(format!("`{iri}` does not exist")));
            }
            let store = storage(iri)?;
            // Remove the fallback first so deletion cannot resurrect legacy text.
            store
                .remove_item(&self.key)
                .and_then(|()| store.remove_item(&self.bytes_key))
                .map_err(|_| Error::Endpoint(format!("delete `{iri}`: localStorage error")))
        }
    }

    pub(super) fn resolve_host_path(_path: &Path) -> Option<PathBuf> {
        None
    }
}

/// Any other native platform: there is no handle-relative, no-follow walk here, so
/// every request is refused rather than served without the jail. (Not compiled by
/// CI, which builds Linux, macOS and wasm32; kept minimal for that reason.)
#[cfg(not(any(unix, target_family = "wasm")))]
mod backend {
    use super::*;

    pub(super) enum Jail {}
    pub(super) enum Found {}

    impl Jail {
        pub(super) fn open(_root: &Path, iri: &str) -> Result<Jail> {
            Err(Error::Endpoint(format!(
                "`{iri}`: ikigai-fs has no confined backend on this platform (it needs \
                 openat); refused rather than served unconfined"
            )))
        }
        pub(super) fn canonical_root(&self) -> Option<PathBuf> {
            match *self {}
        }
        pub(super) fn on_disk_names(&self, _rest: &[OsString]) -> (Vec<OsString>, usize) {
            match *self {}
        }
        pub(super) fn probe(self, _names: &[&str], _iri: &str) -> Result<Found> {
            match self {}
        }
    }

    impl Found {
        pub(super) fn exists(&self) -> bool {
            match *self {}
        }
        pub(super) fn read(self, _iri: &str) -> Result<Vec<u8>> {
            match self {}
        }
        pub(super) fn write(self, _bytes: &[u8], _iri: &str) -> Result<()> {
            match self {}
        }
        pub(super) fn delete(self, _iri: &str) -> Result<()> {
            match self {}
        }
    }

    pub(super) fn resolve_host_path(_path: &Path) -> Option<PathBuf> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ikigai_core::{Bindings, Iri, Request};
    use std::sync::atomic::{AtomicU32, Ordering};

    #[cfg(unix)]
    #[test]
    fn source_read_stays_bounded_when_metadata_understates_the_size() {
        use std::io::{Read, Seek};
        let mut reader = std::io::Cursor::new(vec![b'x'; MAX_FILE_SOURCE_BYTES as usize + 2]);
        let result = backend::read_bounded(&mut reader, 0, "urn:file:growing");
        assert!(matches!(result, Err(Error::OverBudget { .. })));
        assert_eq!(reader.stream_position().unwrap(), MAX_FILE_SOURCE_BYTES + 1);

        // An already oversized file must be rejected before any payload is read.
        let mut reader = std::io::repeat(b'x').take(MAX_FILE_SOURCE_BYTES + 2);
        assert!(matches!(
            backend::read_bounded(
                &mut reader,
                MAX_FILE_SOURCE_BYTES as i64 + 1,
                "urn:file:large"
            ),
            Err(Error::OverBudget { .. })
        ));
        assert_eq!(reader.limit(), MAX_FILE_SOURCE_BYTES + 2);
    }

    #[test]
    fn an_arrangement_file_is_its_own_media_type_not_a_generic_sexpr() {
        assert_eq!(
            media_type_for(Path::new("game.arrangement")).media_type,
            "text/x-ikigai-arrangement"
        );
        assert_eq!(
            source_type("game.arrangement", b"(fallback)", false).media_type,
            "text/x-ikigai-arrangement"
        );
    }

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
        // A capability denial is the typed, permanent `Denied` — never a generic
        // `Endpoint` string, and never transient (re-issuing won't change the answer).
        assert!(matches!(err, Error::Denied(_)));
        assert!(!err.is_transient());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn read_capability_does_not_grant_writes() {
        let root = temp_root();
        let ep = FileEndpoint::new(&root);
        let c = cap(&[&read_scope(&root)]);
        let err = invoke(&ep, Verb::Sink, "new.txt", &c, &[("content", b"x")]).unwrap_err();
        assert!(matches!(err, Error::Denied(_)));
        assert!(!err.is_transient());
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

    #[cfg(unix)]
    #[test]
    fn a_symlink_component_cannot_create_a_file_outside_the_jail() {
        // A new file created *through* a pre-planted symlink must be rejected by
        // the jail, even though the leaf does not exist yet (so `canonicalize`
        // on the target itself fails). Escape would otherwise let
        // `create_dir_all` + `write` follow the link out of the root.
        let root = temp_root();
        let outside = temp_root(); // a distinct dir, not under `root`
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let ep = FileEndpoint::new(&root);
        // Even a root capability (all path-ACLs granted) must not escape.
        let err = invoke(
            &ep,
            Verb::Sink,
            "link/newfile",
            &Capability::root(),
            &[("content", b"pwned")],
        )
        .unwrap_err();
        // A link is a structural refusal (like `..`), not an OS failure.
        assert!(matches!(err, Error::InvalidArgument { .. }), "{err:?}");
        // Nothing was written outside the jail.
        assert!(!outside.join("newfile").exists());
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
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
    fn describe_marks_path_as_a_grammar_binding_on_every_action() {
        use ikigai_core::InputSource;
        let desc = FileEndpoint::new("/tmp").describe();

        // `path` is `{path}` in `urn:file:{path}` — a Binding-source input. The
        // manifold gate (core #84) offers a template action only when every
        // template variable is a declared Binding; without this, the whole
        // grammar stays out of the manifold/catalog/MCP.
        let flat_path = desc.inputs.iter().find(|a| a.name == "path").unwrap();
        assert_eq!(flat_path.source, InputSource::Binding);

        assert_eq!(desc.actions.len(), 4, "four per-verb ActionSpecs");
        for action in &desc.actions {
            let path = action
                .inputs
                .iter()
                .find(|a| a.name == "path")
                .unwrap_or_else(|| panic!("{:?} action declares `path`", action.verb));
            assert_eq!(
                path.source,
                InputSource::Binding,
                "{:?} action's `path` is a grammar binding",
                action.verb
            );
            // The by-value args stay Arguments — only the template variable binds.
            for other in action.inputs.iter().filter(|a| a.name != "path") {
                assert_eq!(other.source, InputSource::Argument, "{}", other.name);
            }
        }
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
            !kernel.is_cached(&source, &cap),
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
        assert!(
            kernel.is_cached(&source(), &cap),
            "cacheable source is cached"
        );

        // Write v2 through the kernel: the Sink auto-cuts `urn:file:notes.txt`.
        let sink = Request::new(Verb::Sink, Iri::parse("urn:file:notes.txt").unwrap())
            .with_arg("content", ikigai_core::ArgRef::Inline(b"v2".to_vec()));
        block_on(kernel.issue(sink, &cap)).unwrap();
        assert!(
            !kernel.is_cached(&source(), &cap),
            "the write invalidated the cached read"
        );

        // Read again: the cache recomputes and sees v2.
        assert_eq!(block_on(kernel.issue(source(), &cap)).unwrap().bytes, b"v2");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cacheable_space_caches_exists_under_the_same_thread_as_the_read() {
        use ikigai_core::Kernel;
        use std::sync::Arc;
        let root = temp_root();
        let kernel = Kernel::new(Arc::new(cacheable_space(&root)));
        let cap = Capability::root();
        let exists = || Request::new(Verb::Exists, Iri::parse("urn:file:later.txt").unwrap());

        // Not yet there: "false", cached under the `urn:file:later.txt` thread.
        assert_eq!(
            block_on(kernel.issue(exists(), &cap)).unwrap().bytes,
            b"false"
        );
        assert!(
            kernel.is_cached(&exists(), &cap),
            "cacheable mode caches the existence answer too"
        );

        // Creating it through the kernel cuts the thread; the answer flips.
        let sink = Request::new(Verb::Sink, Iri::parse("urn:file:later.txt").unwrap())
            .with_arg("content", ikigai_core::ArgRef::Inline(b"now".to_vec()));
        block_on(kernel.issue(sink, &cap)).unwrap();
        assert!(
            !kernel.is_cached(&exists(), &cap),
            "the write invalidated it"
        );
        assert_eq!(
            block_on(kernel.issue(exists(), &cap)).unwrap().bytes,
            b"true"
        );

        // The default mount never caches it: a file is a live fact.
        let live = Kernel::new(Arc::new(space(&root)));
        block_on(live.issue(exists(), &cap)).unwrap();
        assert!(!live.is_cached(&exists(), &cap));
        std::fs::remove_dir_all(&root).ok();
    }

    // --- the one spelling --------------------------------------------------------

    #[test]
    fn a_path_has_one_canonical_spelling() {
        assert_eq!(canonical_names("a/b.txt").unwrap(), ["a", "b.txt"]);
        for (bad, hint) in [
            ("./notes.txt", "`notes.txt`"),
            ("a//b", "`a/b`"),
            ("a/./b", "`a/b`"),
            ("dir/", "`dir`"),
        ] {
            let err = canonical_names(bad).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidArgument { name, detail } if name == "path" && detail.contains(hint)),
                "{bad}: {err:?}"
            );
        }
        for bad in ["", ".", "/abs", "../up", "a/../b", "nul\0byte"] {
            assert!(
                matches!(canonical_names(bad), Err(Error::InvalidArgument { .. })),
                "{bad:?}"
            );
        }
    }

    // --- names with another meaning on Windows (ledger #1319) ------------------------

    /// Names that are one ordinary entry on macOS and Linux and something else on
    /// Windows: a drive prefix (`C:x`, which `Path::join` there lets REPLACE the base), a
    /// rooted or UNC spelling, a `\` separator, an NTFS stream (`notes.txt::$DATA` opens
    /// `notes.txt`), a trailing `.` or space (stripped there, so `notes.txt.` opens
    /// `notes.txt` and walks around a deny on it), or a device name (`CON`, `aux.c`).
    const WINDOWS_MEANINGS: &[&str] = &[
        "C:x",
        "C:",
        "C:/x",
        "dir/C:x",
        r"C:\x",
        r"\\?\C:\x",
        r"\\server\share",
        r"\x",
        r"a\b",
        r"..\x",
        "notes.txt:stream",
        "notes.txt::$DATA",
        "notes.txt.",
        "notes.txt ",
        "...",
        ".. ",
        "CON",
        "con",
        "nul.txt",
        "dir/aux.c",
        "COM1",
        "lpt¹",
        "CONIN$",
        "NUL .txt",
    ];

    /// The lexical half of the jail refuses them on EVERY platform, so a `urn:file:` name
    /// means one file wherever it is served. This is the test that runs on macOS and
    /// Linux, where none of these names would leave the jail.
    #[test]
    fn a_name_with_another_meaning_on_windows_is_refused_on_every_platform() {
        for name in WINDOWS_MEANINGS {
            assert!(
                matches!(canonical_names(name), Err(Error::InvalidArgument { ref name, .. }) if name == "path"),
                "{name:?} must be refused as a path, got {:?}",
                canonical_names(name)
            );
        }
    }

    /// The other side of the rule: names Windows also reads as one ordinary file are kept.
    #[test]
    fn a_name_windows_also_reads_as_one_file_is_kept() {
        for name in [
            "notes.txt",
            "dir/notes.txt",
            "a..b",
            ".hidden",
            "console",
            "COM10",
            "LPT",
            "nullable.txt",
            "auxiliary/con-fig.toml",
            "with space.txt",
        ] {
            assert!(canonical_names(name).is_ok(), "{name:?} is one plain path");
        }
    }

    /// End to end on a Unix volume, where each name is a LEGAL file: planted in the jail,
    /// it is refused before the capability and before the disk, never served and never
    /// written (it used to be read back, and written, as an ordinary file).
    #[cfg(unix)]
    #[test]
    fn a_planted_file_with_a_windows_meaning_is_not_served_on_unix() {
        // A jail per name: `C:` (a file) and `C:/x` (a directory) cannot share one, and
        // `con` would fold onto `CON` on a case-insensitive volume.
        for name in WINDOWS_MEANINGS {
            let root = temp_root();
            let ep = FileEndpoint::new(&root);
            let host = root.join(name);
            std::fs::create_dir_all(host.parent().unwrap()).unwrap();
            std::fs::write(&host, b"planted").unwrap();
            let read = invoke(&ep, Verb::Source, name, &Capability::root(), &[]);
            assert!(
                matches!(read, Err(Error::InvalidArgument { ref name, .. }) if name == "path"),
                "Source {name:?} must be refused, got {read:?}"
            );
            // Structural, so it comes before the capability: an empty one is not `Denied`.
            let bare = invoke(&ep, Verb::Exists, name, &cap(&[]), &[]);
            assert!(
                matches!(bare, Err(Error::InvalidArgument { .. })),
                "Exists {name:?} under no capability must be refused as a path, got {bare:?}"
            );
            let overwrite = invoke(
                &ep,
                Verb::Sink,
                name,
                &Capability::root(),
                &[("content", b"changed")],
            );
            assert!(
                matches!(overwrite, Err(Error::InvalidArgument { .. })),
                "Sink {name:?} must be refused, got {overwrite:?}"
            );
            assert_eq!(std::fs::read(&host).unwrap(), b"planted", "{name:?}");
            std::fs::remove_dir_all(&root).ok();
        }
        let root = temp_root();
        let ep = FileEndpoint::new(&root);
        let fresh = invoke(
            &ep,
            Verb::Sink,
            "D:new.txt",
            &Capability::root(),
            &[("content", b"x")],
        );
        assert!(
            matches!(fresh, Err(Error::InvalidArgument { .. })),
            "{fresh:?}"
        );
        assert!(!root.join("D:new.txt").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    /// Why a Unix-only rule passed every test here: on Unix these names do NOT leave the
    /// directory they are joined to. The premise is observed on Windows below.
    #[cfg(unix)]
    #[test]
    fn on_unix_a_windows_drive_prefix_is_an_ordinary_name() {
        let base = Path::new("/ws");
        for name in ["C:x", r"C:\x", r"\\server\share"] {
            assert!(base.join(name).starts_with(base), "{name:?}");
        }
    }

    /// The premise of ledger #1319, observed where it holds: on Windows a drive-prefixed,
    /// rooted or UNC name REPLACES the base when joined. And what the endpoint does with
    /// each: refused lexically, as a path, before any backend runs; while an ordinary name
    /// is refused by the backend, which has no confined walk on Windows yet. So on Windows
    /// no request reaches the disk at all, today. Runs on the `windows` job in ci.yml.
    #[cfg(windows)]
    #[test]
    fn on_windows_a_drive_prefix_replaces_the_base_and_is_refused() {
        let base = Path::new(r"D:\ws");
        for name in ["C:x", r"C:\x", r"\\?\C:\x", r"\\server\share\x", r"\x"] {
            let joined = base.join(name);
            assert!(
                !joined.starts_with(base),
                "{name:?} joined to {} stayed inside it: {}",
                base.display(),
                joined.display()
            );
        }
        let root = temp_root();
        let ep = FileEndpoint::new(&root);
        for name in WINDOWS_MEANINGS {
            let read = invoke(&ep, Verb::Source, name, &Capability::root(), &[]);
            assert!(
                matches!(read, Err(Error::InvalidArgument { ref name, .. }) if name == "path"),
                "Source {name:?} must be refused as a path, got {read:?}"
            );
        }
        std::fs::write(root.join("notes.txt"), b"x").unwrap();
        let plain = invoke(&ep, Verb::Source, "notes.txt", &Capability::root(), &[]);
        assert!(
            matches!(plain, Err(Error::Endpoint(ref why)) if why.contains("no confined backend")),
            "an ordinary name is refused by the backend on Windows, got {plain:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    // --- the ACL's specificity ------------------------------------------------------

    #[test]
    fn a_scope_on_an_ancestor_of_the_root_covers_the_jail_less_specifically() {
        let root = temp_root();
        std::fs::write(root.join("a.txt"), b"a").unwrap();
        let ep = FileEndpoint::new(&root);
        let parent = root.parent().unwrap();
        // An ancestor grant covers the jail.
        let c = cap(&[&format!("urn:cap:fs:read:{}", parent.display())]);
        assert!(invoke(&ep, Verb::Source, "a.txt", &c, &[]).is_ok());
        // A deny on the root itself outranks an allow on an ancestor…
        let c = cap(&[
            &format!("urn:cap:fs:read:{}", parent.display()),
            &format!("urn:cap:fs:read:-{}", root.display()),
        ]);
        assert!(matches!(
            invoke(&ep, Verb::Source, "a.txt", &c, &[]),
            Err(Error::Denied(_))
        ));
        // …and an allow on the root outranks a deny on an ancestor (more specific).
        let c = cap(&[
            &format!("urn:cap:fs:read:-{}", parent.display()),
            &read_scope(&root),
        ]);
        assert!(invoke(&ep, Verb::Source, "a.txt", &c, &[]).is_ok());
        // An allow spelled with `..` is ignored rather than resolved.
        let c = cap(&[&format!("urn:cap:fs:read:{}/x/..", root.display())]);
        assert!(invoke(&ep, Verb::Source, "a.txt", &c, &[]).is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_deny_on_a_name_not_yet_on_disk_binds_without_regard_to_case() {
        let root = temp_root();
        let ep = FileEndpoint::new(&root);
        let c = cap(&[
            &write_scope(&root),
            &format!("urn:cap:fs:write:-{}", root.join("Drafts").display()),
        ]);
        // `drafts/` does not exist, so the volume cannot say whether it is `Drafts/`.
        let err = invoke(&ep, Verb::Sink, "drafts/x.txt", &c, &[("content", b"x")]).unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        assert!(!root.join("drafts").exists(), "nothing was created");
        // An ALLOW is never widened that way.
        let c = cap(&[&format!(
            "urn:cap:fs:write:{}",
            root.join("Public").display()
        )]);
        let err = invoke(&ep, Verb::Sink, "public/x.txt", &c, &[("content", b"x")]).unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        std::fs::remove_dir_all(&root).ok();
    }

    // --- links, kinds and handles (native) ------------------------------------------

    #[cfg(unix)]
    #[test]
    fn every_verb_refuses_a_link_leaf_and_a_link_directory() {
        let root = temp_root();
        std::fs::create_dir(root.join("real")).unwrap();
        std::fs::write(root.join("real/f.txt"), b"x").unwrap();
        std::os::unix::fs::symlink("real/f.txt", root.join("leaf-link")).unwrap();
        std::os::unix::fs::symlink("real", root.join("dir-link")).unwrap();
        let ep = FileEndpoint::new(&root);
        let all = Capability::root();
        for path in ["leaf-link", "dir-link/f.txt"] {
            for verb in [Verb::Source, Verb::Exists, Verb::Delete] {
                let err = invoke(&ep, verb, path, &all, &[]).unwrap_err();
                assert!(
                    matches!(err, Error::InvalidArgument { .. }),
                    "{verb:?} {path}: {err:?}"
                );
            }
            let err = invoke(&ep, Verb::Sink, path, &all, &[("content", b"y")]).unwrap_err();
            assert!(
                matches!(err, Error::InvalidArgument { .. }),
                "Sink {path}: {err:?}"
            );
        }
        assert_eq!(std::fs::read(root.join("real/f.txt")).unwrap(), b"x");
        assert!(
            root.join("leaf-link").symlink_metadata().is_ok(),
            "the link itself survives"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn directories_and_files_in_the_way_are_named_not_followed() {
        let root = temp_root();
        std::fs::create_dir(root.join("dir")).unwrap();
        std::fs::write(root.join("file.txt"), b"x").unwrap();
        let ep = FileEndpoint::new(&root);
        let all = Capability::root();
        // A directory is not a file, for any verb that needs one.
        for verb in [Verb::Source, Verb::Delete] {
            let err = invoke(&ep, verb, "dir", &all, &[]).unwrap_err();
            assert!(
                matches!(err, Error::InvalidArgument { .. }),
                "{verb:?}: {err:?}"
            );
        }
        assert!(root.join("dir").is_dir());
        // A file named as a directory: absent to a read, refused to a write.
        let exists = invoke(&ep, Verb::Exists, "file.txt/x", &all, &[]).unwrap();
        assert_eq!(exists.bytes, b"false");
        assert!(matches!(
            invoke(&ep, Verb::Source, "file.txt/x", &all, &[]),
            Err(Error::NotFound(_))
        ));
        assert!(matches!(
            invoke(&ep, Verb::Sink, "file.txt/x", &all, &[("content", b"y")]),
            Err(Error::InvalidArgument { .. })
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_sink_that_fails_after_a_short_write_preserves_the_old_file() {
        use std::io::Write;
        let root = temp_root();
        std::fs::write(root.join("f"), b"old complete content").unwrap();
        let found = backend::probe_for_test(&root, &["f"]).unwrap();
        let result = found.write_with("urn:file:f", |file| {
            file.write_all(b"new prefix")?;
            Err(std::io::Error::other(
                "injected disk-full after a short write",
            ))
        });
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(root.join("f")).unwrap(),
            b"old complete content"
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_source_during_a_sink_sees_only_complete_content() {
        use std::io::Write;
        let root = temp_root();
        std::fs::write(root.join("f"), b"old complete content").unwrap();
        let already_open = backend::probe_for_test(&root, &["f"]).unwrap();
        let found = backend::probe_for_test(&root, &["f"]).unwrap();
        found
            .write_with("urn:file:f", |file| {
                file.write_all(b"new prefix")?;
                // The writer is paused after a real short write while a separate
                // thread executes Source through the endpoint and its jail checks.
                let observed = std::thread::scope(|scope| {
                    scope
                        .spawn(|| {
                            invoke(
                                &FileEndpoint::new(&root),
                                Verb::Source,
                                "f",
                                &Capability::root(),
                                &[],
                            )
                            .unwrap()
                            .bytes
                        })
                        .join()
                        .unwrap()
                });
                assert_eq!(observed, b"old complete content");
                file.write_all(b" and suffix")
            })
            .unwrap();
        assert_eq!(
            backend::probe_for_test(&root, &["f"])
                .unwrap()
                .read("urn:file:f")
                .unwrap(),
            b"new prefix and suffix"
        );
        // A probe from before publication must refuse the new inode.
        assert!(already_open.read("urn:file:f").is_err());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_new_sink_is_absent_until_complete_and_absent_on_failure() {
        use std::io::Write;
        let root = temp_root();
        for fail in [true, false] {
            let result =
                backend::probe_for_test(&root, &["f"])
                    .unwrap()
                    .write_with("urn:file:f", |file| {
                        file.write_all(b"prefix")?;
                        assert!(matches!(
                            backend::probe_for_test(&root, &["f"])
                                .unwrap()
                                .read("urn:file:f"),
                            Err(Error::NotFound(_))
                        ));
                        if fail {
                            return Err(std::io::Error::other("injected failure"));
                        }
                        file.write_all(b" suffix")
                    });
            if fail {
                assert!(result.is_err());
                assert!(!root.join("f").exists());
                assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
            } else {
                result.unwrap();
                assert_eq!(std::fs::read(root.join("f")).unwrap(), b"prefix suffix");
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_sink_refuses_leaf_changes_before_and_during_staging() {
        use std::io::Write;
        for existing in [true, false] {
            for during in [true, false] {
                let root = temp_root();
                if existing {
                    std::fs::write(root.join("f"), b"original").unwrap();
                }
                let found = backend::probe_for_test(&root, &["f"]).unwrap();
                let swap = || {
                    if existing {
                        std::fs::rename(root.join("f"), root.join("old")).unwrap();
                    }
                    std::fs::write(root.join("f"), b"substitute").unwrap();
                };
                if !during {
                    swap();
                }
                let result = found.write_with("urn:file:f", |file| {
                    file.write_all(b"prefix")?;
                    if during {
                        swap();
                    }
                    file.write_all(b" suffix")
                });
                assert!(result.is_err());
                assert_eq!(std::fs::read(root.join("f")).unwrap(), b"substitute");
                if existing {
                    assert_eq!(std::fs::read(root.join("old")).unwrap(), b"original");
                }
                assert_eq!(
                    std::fs::read_dir(&root).unwrap().count(),
                    if existing { 2 } else { 1 }
                );
                std::fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replacement_preserves_permissions_and_open_readers() {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        let root = temp_root();
        std::fs::write(root.join("f"), b"original").unwrap();
        std::fs::set_permissions(root.join("f"), std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::hard_link(root.join("f"), root.join("alias")).unwrap();
        let mut reader = std::fs::File::open(root.join("f")).unwrap();
        backend::probe_for_test(&root, &["f"])
            .unwrap()
            .write(b"replacement", "urn:file:f")
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        assert_eq!(std::fs::read(root.join("alias")).unwrap(), b"original");
        assert_eq!(std::fs::read(root.join("f")).unwrap(), b"replacement");
        assert_eq!(
            std::fs::metadata(root.join("f"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// B7, deterministic: the swap happens exactly between the walk (the check) and
    /// the write (the use). The write lands in the directory the walk opened, which
    /// was judged; the link put in its place is never consulted.
    #[cfg(unix)]
    #[test]
    fn a_swap_after_the_walk_cannot_redirect_the_write() {
        let root = temp_root();
        let outside = temp_root();
        std::fs::create_dir(root.join("d")).unwrap();
        let found = backend::probe_for_test(&root, &["d", "f"]).unwrap();
        std::fs::rename(root.join("d"), root.join("d-moved")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("d")).unwrap();
        found.write(b"x", "urn:file:d/f").unwrap();
        assert!(
            !outside.join("f").exists(),
            "the write followed the swapped-in link"
        );
        assert_eq!(std::fs::read(root.join("d-moved/f")).unwrap(), b"x");
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// The same, for a directory the write has to CREATE: a link planted where the
    /// walk saw nothing is refused at the descent, not followed.
    #[cfg(unix)]
    #[test]
    fn a_link_planted_where_a_directory_is_about_to_be_created_is_refused() {
        let root = temp_root();
        let outside = temp_root();
        let found = backend::probe_for_test(&root, &["d", "f"]).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("d")).unwrap();
        let err = found.write(b"x", "urn:file:d/f").unwrap_err();
        assert!(matches!(err, Error::InvalidArgument { .. }), "{err:?}");
        assert!(!outside.join("f").exists());
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// And for the leaf: swapped for a link, or for another file, after the walk.
    #[cfg(unix)]
    #[test]
    fn a_leaf_swapped_after_the_walk_is_not_read_or_written() {
        let root = temp_root();
        let outside = temp_root();
        std::fs::write(outside.join("secret"), b"OUTSIDE").unwrap();
        std::fs::write(root.join("f"), b"inside").unwrap();

        let found = backend::probe_for_test(&root, &["f"]).unwrap();
        std::fs::remove_file(root.join("f")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), root.join("f")).unwrap();
        assert!(matches!(
            found.read("urn:file:f"),
            Err(Error::InvalidArgument { .. })
        ));
        let found = backend::probe_for_test(&root, &["f"]);
        assert!(
            matches!(found, Err(Error::InvalidArgument { .. })),
            "a link leaf is refused at the walk"
        );

        std::fs::remove_file(root.join("f")).unwrap();
        std::fs::write(root.join("f"), b"inside").unwrap();
        let found = backend::probe_for_test(&root, &["f"]).unwrap();
        std::fs::remove_file(root.join("f")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), root.join("f")).unwrap();
        assert!(found.write(b"pwned", "urn:file:f").is_err());
        assert_eq!(std::fs::read(outside.join("secret")).unwrap(), b"OUTSIDE");

        std::fs::remove_file(root.join("f")).unwrap();
        std::fs::write(root.join("f"), b"one").unwrap();
        let found = backend::probe_for_test(&root, &["f"]).unwrap();
        std::fs::rename(root.join("f"), root.join("g")).unwrap();
        std::fs::write(root.join("f"), b"two").unwrap();
        assert!(
            matches!(found.read("urn:file:f"), Err(Error::Endpoint(_))),
            "a different inode than the one judged is refused, not read"
        );
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }
}

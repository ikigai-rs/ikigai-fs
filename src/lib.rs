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
//!    read or write happens on the handle that walk produced — so nothing can be
//!    swapped in between the check and the use. A root that cannot be opened
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
//!   `notes.txt` on a case-insensitive (or normalization-insensitive) volume.
//!
//! So the request IRI *is* the file's identity: the ACL judges the path that is
//! opened, and the golden thread a read hangs from is the one every write to that
//! file cuts (the kernel auto-cuts a write's own target). Hard links remain
//! distinct names for one file, as they are to the filesystem.
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
//! ⚠ **A deny is an ordinary scope, so attenuation and transport clamps can drop
//! it** — and dropping an exclusion widens access. Until core gives exclusions a
//! form that `attenuate`/`clamp` never drop (ledger #858), do not rely on a `-path`
//! scope surviving delegation or a hop over the wire.
//!
//! ## Representations
//!
//! `Source` hands back a **string by default** (a known text media type from the
//! extension, or `text/plain` when the bytes decode as UTF-8); pass `as` =
//! `application/octet-stream` to get the raw **bytes** instead. Any other `as` is
//! refused: this endpoint does not convert, so it will not relabel. `Sink` writes
//! the `content` argument's bytes. A missing file is the typed
//! [`Error::NotFound`]. Errors name the request's IRI, never a host path. Reads
//! (and `Exists` answers) are **uncacheable by default** — a file is a live fact —
//! but a mount can opt into caching them under a **golden thread**
//! ([`FileEndpoint::cacheable`] / [`cacheable_space`]): a `Sink`/`Delete` through
//! the kernel then invalidates the cached read (requires `ikigai-core` ≥ 0.1.9).
//!
//! The module passes `ikigai-conformance` (`tests/conformance.rs`) on both
//! mounts, with no opt-outs.
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

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, ArgSpec, Capability, Description, Endpoint, EndpointSpace, Error, Invocation,
    ReprType, Representation, Result, UriTemplate, Verb,
};

/// The conventional grammar a host mounts this module at: `urn:file:{path}`,
/// where `{path}` is captured root-relative and handed to the endpoint as the
/// `path` binding (so the file's *identity* is the request, not an argument).
pub const FILE_TEMPLATE: &str = "urn:file:{path}";

/// The datatype every input of this module carries: a root-relative path, a
/// media type, and the bytes to write all arrive as strings on the wire and in
/// an agent's tool call. (The bytes are not base64 — `content` is the payload
/// itself, which the wasm backend additionally requires to be UTF-8.)
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

/// A file endpoint jailed to a root directory, gated by the capability path-ACL.
pub struct FileEndpoint {
    root: PathBuf,
    cacheable: bool,
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
        }
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
    /// thread. Enable only where that staleness window is acceptable (e.g. a root
    /// written through ikigai), until the watch policy lands.
    pub fn cacheable(mut self) -> Self {
        self.cacheable = true;
        self
    }
}

#[async_trait]
impl Endpoint for FileEndpoint {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
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

        match verb {
            Verb::Source => {
                let bytes = found.read(iri)?;
                let leaf = names.last().copied().unwrap_or_default();
                let repr = Representation::new(source_type(leaf, &bytes, raw), bytes);
                if self.cacheable {
                    // Cache under a golden thread named after the resource. A
                    // `Sink`/`Delete` (kernel auto-cut) — or an external watcher —
                    // invalidates it. The IRI is the file's only name (aliases are
                    // refused above), so the write that changes the file is the one
                    // that cuts this thread. All representations of the file
                    // (string, raw bytes) share it.
                    Ok(repr.cacheable().depends_on(iri))
                } else {
                    // Default: a file is a live fact, recomputed every read.
                    Ok(repr)
                }
            }
            Verb::Sink => {
                let content = inv.inline_arg("content")?;
                found.write(content, iri)?;
                Ok(ack(format!("wrote {} bytes to {rel}", content.len())))
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
                    .summary("Bytes to write (Sink only).")
                    .class(XSD_STRING)
                    .optional(),
            )
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
                    .output(OCTET_STREAM),
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
                    .input(
                        ArgSpec::new("content")
                            .summary("the bytes to write")
                            .class(XSD_STRING),
                    )
                    .output("text/plain;charset=utf-8"),
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
/// empty, none `.` or `..`, not absolute — so two IRIs can never name one file through
/// spelling alone. A refusal of a non-canonical spelling names the canonical one.
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
    if kept.len() != names.len() {
        return Err(deny(&format!(
            "`{rel}` is not a canonical spelling (no `.`, empty segments or trailing `/`); \
             name the file `{}`",
            kept.join("/")
        )));
    }
    Ok(names)
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
            let Some(stat) = self.leaf.as_ref() else {
                return Err(not_found(iri));
            };
            require_regular(stat, &self.shown())?;
            let fd = rfs::openat(
                &self.dir,
                self.leaf_name(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|e| match e {
                Errno::LOOP | Errno::MLINK => link_refused_shown(&self.shown()),
                e => io_error("read", iri, e),
            })?;
            // The handle is the file judged: the same inode the walk found, still a
            // regular file. Anything else was swapped in since.
            let now = rfs::fstat(&fd).map_err(|e| io_error("read", iri, e))?;
            if now.st_ino != stat.st_ino || now.st_dev != stat.st_dev {
                return Err(changed(iri));
            }
            require_regular(&now, &self.shown())?;
            let mut bytes = Vec::new();
            std::fs::File::from(fd)
                .read_to_end(&mut bytes)
                .map_err(|e| Error::Endpoint(format!("read `{iri}`: {e}")))?;
            Ok(bytes)
        }

        pub(super) fn write(self, bytes: &[u8], iri: &str) -> Result<()> {
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
            // The leaf: never through a link, and created exclusively when the walk
            // saw nothing there (so a name that appeared meanwhile is not adopted
            // under a spelling nobody checked). Truncated only once the handle is
            // known to be a regular file.
            let mut flags = OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
            if self.leaf.is_none() {
                flags |= OFlags::CREATE | OFlags::EXCL;
            }
            let fd = rfs::openat(
                &dir,
                *all.last().expect("non-empty"),
                flags,
                Mode::from_raw_mode(0o666),
            )
            .map_err(|e| match e {
                Errno::LOOP | Errno::MLINK => link_refused_shown(&shown),
                // EXIST: the name appeared since the walk; NOENT: it went away.
                Errno::EXIST | Errno::NOENT => changed(iri),
                Errno::ISDIR => deny(&format!("`{shown}` is a directory, not a file")),
                e => io_error("write", iri, e),
            })?;
            let stat = rfs::fstat(&fd).map_err(|e| io_error("write", iri, e))?;
            require_regular(&stat, &shown)?;
            rfs::ftruncate(&fd, 0).map_err(|e| io_error("write", iri, e))?;
            std::fs::File::from(fd)
                .write_all(bytes)
                .map_err(|e| Error::Endpoint(format!("write `{iri}`: {e}")))
        }

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
/// `localStorage` holds UTF-16 strings, so this backend is text-oriented: a write
/// of non-UTF-8 bytes is refused (binary would need an encoding such as base64 —
/// a later step). The REPL's `sink`/`source` are text, which is the intended use.
#[cfg(target_family = "wasm")]
mod backend {
    use super::*;

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
            let present = storage(iri)?
                .get_item(&key)
                .map_err(|_| Error::Endpoint(format!("exists `{iri}`: localStorage error")))?
                .is_some();
            Ok(Found { key, present })
        }
    }

    pub(super) struct Found {
        key: String,
        present: bool,
    }

    impl Found {
        pub(super) fn exists(&self) -> bool {
            self.present
        }

        pub(super) fn read(self, iri: &str) -> Result<Vec<u8>> {
            let value = storage(iri)?
                .get_item(&self.key)
                .map_err(|_| Error::Endpoint(format!("read `{iri}`: localStorage error")))?;
            match value {
                Some(text) => Ok(text.into_bytes()),
                None => Err(Error::NotFound(format!("`{iri}` does not exist"))),
            }
        }

        pub(super) fn write(self, bytes: &[u8], iri: &str) -> Result<()> {
            let text = std::str::from_utf8(bytes).map_err(|_| {
                Error::Endpoint(format!(
                    "write `{iri}`: the localStorage backend stores UTF-8 text (binary needs base64)"
                ))
            })?;
            storage(iri)?
                .set_item(&self.key, text)
                .map_err(|_| Error::Endpoint(format!("write `{iri}`: localStorage error (quota?)")))
        }

        pub(super) fn delete(self, iri: &str) -> Result<()> {
            if !self.present {
                return Err(Error::NotFound(format!("`{iri}` does not exist")));
            }
            storage(iri)?
                .remove_item(&self.key)
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

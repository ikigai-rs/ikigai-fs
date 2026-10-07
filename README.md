# ikigai-fs

A capability-gated **file/store module** for [ikigai](https://github.com/ikigai-rs) —
a standalone module crate (like `ikigai-fn` / `ikigai-personal`) that a host links
in and mounts with [`space`], rather than the engine shipping file behavior itself.
It depends only on the published `ikigai-core` kernel and compiles for both native
and `wasm32` hosts.

Files are the most dangerous endpoint in the system — arbitrary filesystem read
*and* write — so access is confined by **two independent layers, both required on
every request**, and both judge **the file actually opened**:

1. **The jail (structural, mount-time).** `FileEndpoint::new(root)` will never
   serve a file outside `root`. The request path is walked one name at a time from
   an open handle on the root (`openat`, `O_NOFOLLOW`), and the read or write
   happens on the handle that walk produced, so nothing can be swapped in between
   the check and the use. A root that cannot be opened serves nothing: the jail
   fails closed, and the endpoint never creates its own root. Even a `root`
   capability cannot escape it.
2. **The capability path-ACL (dynamic, per request).** The invocation's
   `Capability` must grant the request's action for that path.

> **Scope of protection.** This model governs the **resource-oriented** surface
> only: what is reachable by *resolving* `urn:file:` resources through the ikigai
> kernel (`Source`/`Sink`/`Exists`/`Delete`). It is a resource-model protection,
> not yet a hardened OS or process sandbox — code that bypasses resolution (a
> loaded module making direct syscalls, or native code touching the filesystem
> outside this endpoint) is not constrained by these layers. A more formal
> **capabilities-based sandbox is coming**: ikigai capabilities will drive a
> platform sandbox (WASI / `wasmtime`), so the resource model controls what the
> platform allows the code running on it. The jail here is precisely a native
> preview of a WASI preopen.

## One file, one name

A file is served under exactly one spelling: its path **as it is on disk**,
relative to the root. Every other way of naming it is refused with
`InvalidArgument` (a refusal no retry changes):

| refused | why |
|---------|-----|
| a symbolic link anywhere in the path (leaf or directory, in the jail or out) | the file opened would differ from the path authorized |
| `./notes.txt`, `a//b`, `dir/` | a second IRI for one file; the error names the canonical spelling |
| `..`, an absolute path | outside the jail |
| `NOTES.txt` for `notes.txt` on a case-insensitive volume (macOS's default), or a different Unicode normalization of the name | the volume folds it onto another name |

Two consequences follow. The ACL judges exactly the path that is opened. And the
request IRI **is** the file's identity, so in the cacheable mode the golden thread a
read hangs from is the one every write to that file cuts. Hard links remain
distinct names for one file, as they are to the filesystem.

## Capability scopes

Carried as `urn:cap:fs:<action>:<path>` scopes, where `<action>` is `read` /
`write` / `delete` and `<path>` is a directory or file. A leading `-` marks a
**deny**:

| scope | effect |
|-------|--------|
| `urn:cap:fs:read:/ws` | read anything under `/ws` |
| `urn:cap:fs:read:/ws/public` (only) | allowlist — read just that subtree |
| `urn:cap:fs:read:/ws` + `urn:cap:fs:read:-/ws/secret` | read `/ws` except `secret` |

A scope is placed into the jail before it is matched. Its path is normalized (`.`,
repeated and trailing `/` dropped), then placed against the root under **either of
the root's spellings** — as mounted, or canonical, so `/private/var/…` and `/var/…`
name one jail on macOS — and the part inside the jail is resolved to its on-disk
names. A scope naming the root or an ancestor of it covers the whole jail.

Matching is **most specific wins, by path depth; deny breaks ties**; no matching
rule is **default-deny**; a `root` capability allows everything *within the jail*.
A deny that names something not yet on disk is compared without regard to case
(the volume's rule for a name that does not exist cannot be read off the volume),
which can only over-deny; an allow is never widened that way. These are
owner-minted rule sets — the flat-scope `Capability` is untouched and this module
does the path-aware matching.

> ⚠ **Known gap: a `-path` deny does not survive attenuation or a transport
> clamp.** A deny is an ordinary scope, and core's `Capability::attenuate` (keep a
> subset) and `Capability::clamp` (intersect) may drop it — and dropping an
> exclusion *widens* access. A delegate attenuated to `{read:/ws}` from
> `{read:/ws, read:-/ws/secret}` reads `secret`, and so does a peer clamped to a
> ceiling that carries the deny. Until core gives exclusions a form that is never
> dropped (ledger #858), express a boundary that must survive delegation or the
> wire as an **allowlist** (grant the subtrees, deny nothing), or jail the
> delegate to its own root. `tests/audit_regressions.rs` pins today's behavior as
> `known_gap_858_…`, so the day it changes the test says so.

## Verbs

- `Source` — read; yields a **string by default** (known text type, or
  `text/plain` when the bytes are valid UTF-8), or raw bytes with
  `as=application/octet-stream`. **Any other `as` is refused** — the endpoint
  does not convert, so it will not relabel. Uncacheable (a file is a live fact).
- `Sink` — write the `content` argument's bytes, creating missing directories.
- `Exists` / `Delete` — existence check (a read) and removal (a delete).

A missing file is the typed `NotFound` (for `Source` and `Delete`; `Exists`
answers `false`). Errors name the request's IRI, never the host path behind it.
A failed check is an error, never a `false`.

Every input is typed (`xsd:string`) and `path` is declared as the `{path}`
binding of the grammar on every action, so the whole `urn:file:*` grammar is
selectable from the action manifold and projects as one well-typed MCP tool.

## Mounting

```rust
let kernel = Kernel::new(Arc::new(ikigai_fs::space("/Users/me/workspace")));
// resolve `urn:file:notes.txt` under a capability scoped within the root
```

`cacheable_space` is the opt-in alternative: `Source` reads **and** `Exists`
answers are cached under a golden thread named after the resource, and a
`Sink`/`Delete` through the kernel cuts it. Out-of-band changes are not seen
until something cuts the thread, so use it for a root written through ikigai.

## Conformance

The module **passes
[`ikigai-conformance`](https://github.com/ikigai-rs/ikigai-conformance)** with
no opt-outs, on both mounts: `tests/conformance.rs` builds a jail over a fresh
temporary directory (the suite fires `Sink`, so the kernel under test is a
fixture) and runs every check — ArgSpec completeness, template drivability,
declared = enforced via the path-ACL floor, cacheability, pipeline citizenship,
naming. The cacheable mount is declared `cacheable` there and held to it; the
endpoint is deliberately **not** declared `pure` — its results depend on the
file — so a cached read with an empty golden-thread set would fail the test.

`tests/audit_regressions.rs` holds every reproduction from audit round 3 (ledger
#856); each failed on 0.1.7 because of the defect it names.

## Platforms

One crate, a `cfg`-gated backend.

- **Unix (Linux, macOS)** — the handle-relative, no-follow walk above, through
  [`rustix`](https://crates.io/crates/rustix) (safe wrappers over `openat`,
  `statat`, `mkdirat`, `unlinkat`; no `unsafe` here). Confirming a name's on-disk
  spelling reads its directory, so a directory the host lets the process search
  but not list cannot be served through.
- **`wasm32`** — the browser's `localStorage` (keyed `ikigai:fs:<root>/<path>`).
  Same `file:` contract and `urn:cap:fs` scopes; there are no links or case
  folding there, so the spelling rules are the whole jail. Text-oriented (it
  refuses non-UTF-8 writes).
- **Any other native platform** (Windows) has no confined backend yet and
  **refuses every request** rather than serve one unconfined.

## 0.1.8 (2026-10-07)

**Version call: 0.1.8 (a patch), not 0.2.0.** No public API changes (the same
`space`, `cacheable_space`, `FileEndpoint`, `FILE_TEMPLATE`), and these are security
fixes that should reach every consumer through its existing `0.1` caret; a 0.2.0
would leave each one on the vulnerable 0.1.7 until it moved its pin. But the
behavior changes, and a host that leaned on the old behavior will see refusals
where it saw answers:

- **Symbolic links are refused** anywhere in a request path (they were followed
  when they stayed inside the jail). Closes the dangling-link write out of the
  jail, the in-jail link around a deny, and the allowlisted subtree written outside
  itself through a link.
- **Non-canonical spellings are refused** (`./x`, `a//b`, `dir/`, and case or
  normalization variants on folding volumes), so no alias of a file can serve a
  stale cached read or existence answer after a write through another spelling.
- **A root that cannot be opened fails closed** (containment was skipped), and the
  endpoint no longer creates a missing root.
- **The read and the write happen on the handle the jail check produced**, which
  closes the check-then-use race (a directory swapped for a link mid-request).
- **Rule specificity is path depth**, not the scope string's length, so
  `/ws/secret/` and `/ws/secret` are one directory and a deny wins the tie.
- **Scopes match under the root's canonical spelling** as well as the mounted one
  (part of ledger #230).
- **`as` other than `application/octet-stream` is refused** on `Source` (any value
  used to relabel the bytes, CRLF included).
- **A missing file is `NotFound`** (was a generic `Endpoint` error), errors no
  longer carry host paths, and `Exists` reports a failed check instead of `false`.
- Windows refuses every request (it ran the path-checking jail these fixes replace).

## License

MIT OR Apache-2.0

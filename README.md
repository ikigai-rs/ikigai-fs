# ikigai-fs

A capability-gated **file/store module** for [ikigai](https://github.com/ikigai-rs) —
a standalone module crate (like `ikigai-fn` / `ikigai-personal`) that a host links
in and mounts with [`space`], rather than the engine shipping file behaviour itself.
It depends only on the published `ikigai-core` kernel and compiles for both native
and `wasm32` hosts.

Files are the most dangerous endpoint in the system — arbitrary filesystem read
*and* write — so access is confined by **two independent layers, both required on
every request**:

1. **The jail (structural, mount-time).** `FileEndpoint::new(root)` will never
   serve a path outside `root`: `..` and absolute segments are rejected, and an
   existing target's canonical path must still sit within the canonical root
   (symlink-safe). Even a `root` capability cannot escape it.
2. **The capability path-ACL (dynamic, per request).** The invocation's
   `Capability` must grant the request's action for the resolved path.

## Capability scopes

Carried as `urn:cap:fs:<action>:<path>` scopes, where `<action>` is `read` /
`write` / `delete` and `<path>` is an absolute directory or file. A leading `-`
marks a **deny**:

| scope | effect |
|-------|--------|
| `urn:cap:fs:read:/ws` | read anything under `/ws` |
| `urn:cap:fs:read:/ws/public` (only) | allowlist — read just that subtree |
| `urn:cap:fs:read:/ws` + `urn:cap:fs:read:-/ws/secret` | read `/ws` except `secret` |

Matching is **longest-prefix wins, deny breaks ties**; no matching rule is
**default-deny**; a `root` capability allows everything *within the jail*. These
are owner-minted rule sets — the flat-scope `Capability` is untouched and this
module does the path-aware matching.

## Verbs

- `Source` — read; yields a **string by default** (known text type, or
  `text/plain` when the bytes are valid UTF-8), or raw bytes with
  `as=application/octet-stream`. Uncacheable (a file is a live fact).
- `Sink` — write the `content` argument's bytes.
- `Exists` / `Delete` — existence check (a read) and removal (a delete).

## Mounting

```rust
let kernel = Kernel::new(Arc::new(ikigai_fs::space("/Users/me/workspace")));
// resolve `urn:file:notes.txt` under a capability scoped within the root
```

## Platforms

One crate, a `cfg`-gated backend. Native uses jailed `std::fs`. The `wasm32`
backend (browser `localStorage`) is planned and currently returns a "not yet
implemented" error, so the module still compiles and links into the in-browser
host.

## License

MIT OR Apache-2.0

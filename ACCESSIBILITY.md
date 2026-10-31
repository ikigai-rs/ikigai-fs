# Accessibility

What `ikigai-fs` emits that people read, the rules that output follows, how it is tested, and
how to report a barrier. It is a library: it answers `urn:file:` requests with text, and a host
decides how a person sees it. It is not a conformance claim. Adapted from the
[ACCESSIBILITY.md template](https://github.com/mgifford/ACCESSIBILITY.md) (MIT).

| Field | Value |
|---|---|
| Target | WCAG 2.2 Level AA, for any page that presents this output; this repository writes text only, no HTML or SVG |
| Status | Evaluation in progress. No conformance claim. |
| Owner | the maintainers of this repository |
| Report a barrier | [a GitHub issue](https://github.com/ikigai-rs/ikigai-fs/issues/new?labels=accessibility) with the `accessibility` label; anything security-sensitive through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-fs/security/advisories/new) |
| Last reviewed | 2026-10-31 |

## What it emits that people read

All of it is in `src/lib.rs` unless named otherwise.

- **Refusals and errors**: the details of the errors the `file` endpoint returns, for example
  `` `notes.txt.` `` refused because the name means something else on Windows, a path that is
  not its canonical spelling (with the spelling to use instead), a name that is not its on-disk
  spelling, a symbolic link, a directory where a file was asked for, a missing file
  (`` `urn:file:x` does not exist ``), a capability that does not grant the action, a write past
  the root's ceiling, a read past the Source limit, a file that changed while read, and an `as`
  this endpoint does not serve. The spill store (`src/spill.rs`) has its own errors.
- **Acknowledgements** (`text/plain`): `wrote N bytes to <path>` for a `Sink`, `deleted <path>`
  for a `Delete`, and `true` or `false` for an `Exists`.
- **Directory listings**: a directory's `Source` is its child names, sorted, one per line
  (`text/plain`), or their full `urn:file:` URIs under `as=text/uri-list`.
- **The endpoint's self-description**: the summaries of the `file` endpoint, its actions and
  arguments, which a host shows in its catalog, help or tool list.

Not this repository's: the words around an error (`Error`'s `Display`, from `ikigai-core`), the
operating system's own error text that some messages carry after a colon, the contents of the
files it serves, and any page, terminal or tool that shows them. This repository has no binary,
so it writes nothing to a terminal.

## The rules that output follows

- A message about a request names the request's own `urn:file:` IRI or path, never the host path
  behind it.
- A refusal of a path says why in words, and where there is one right spelling it names it
  (``name the file `a/b` ``).
- A refusal that the caller can fix by acting says so: a file that changed while read says
  `read it again`, one that changed while served says `retry`, and an unsupported `as` lists the
  values that are served.
- No color, no terminal control codes and no markup are written.

## How it is tested

- `tests/audit_regressions.rs`'s `f4_errors_never_name_the_host_path` pins that a read, a delete
  and two writes that fail never name the host path.
- `src/lib.rs`'s `a_path_has_one_canonical_spelling` pins that a non-canonical path is refused
  with the spelling to use.
- `tests/bodies.rs`, `tests/reads_body.rs` and `tests/sink_encoding.rs` pin the `wrote N bytes
  to <path>` acknowledgement; `tests/bodies.rs` pins `changed while read`;
  `tests/max_write.rs`'s `one_byte_past_the_ceiling_is_refused_with_nothing_left_behind` pins
  that the refusal states the ceiling.
- `tests/listing.rs`'s `a_directory_sources_as_the_newline_list_of_its_child_names` pins the
  listing's form.

The other messages are followed by reading and not tested. **No automated accessibility checker,
browser or assistive technology has been used on this output.**

## Known limitations

Found by reading the source on 2026-10-31, not by testing:

- A directory listing does not say which names are directories: a subdirectory is listed exactly
  as a file is.
- `file endpoint does not support the … verb` names the verb in its Rust spelling and does not
  name the request.
- On the browser (`wasm32`) backend, a storage failure says only `localStorage error`, and a
  failed write adds `(quota?)`, a guess; neither says what to do.
- `stage … temporary name collisions` and `spill: temporary name collisions` say what failed but
  not what to do.
- The spill store's errors (`src/spill.rs`) name its directory as a host path; it is the host's
  own configuration, not a request's.

## Contributing

Read this file before changing any output listed above: an error's words, an acknowledgement, a
listing or the endpoint's description. Keep meaning in words, name the request a message is
about, and never the host path. Say in the pull request what was tested, with what, and what was
not.

## Reporting a barrier

[Open an issue](https://github.com/ikigai-rs/ikigai-fs/issues/new?labels=accessibility) with
the `accessibility` label (the link sets it when GitHub lets you add labels; otherwise a
maintainer adds it): what you were doing, what happened, and any assistive technology you use,
if you are comfortable sharing it. Anything security-sensitive goes through
[private vulnerability reporting](https://github.com/ikigai-rs/ikigai-fs/security/advisories/new).
**We acknowledge a report within 7 days**, and promise nothing further.

## Change history

| Date | Change |
|---|---|
| 2026-10-31 | First version. |

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
| Last reviewed | 2026-11-12 |

## What it emits that people read

All of it is in `src/lib.rs` unless named otherwise.

- **Refusals and errors**: the details of the errors the `file` endpoint returns, for example
  `` `notes.txt.` `` refused because the name means something else on Windows, a path that is
  not its canonical spelling (with the spelling to use instead), a name that is not its on-disk
  spelling, a symbolic link, a directory where a file was asked for, a missing file
  (`` `urn:file:x` does not exist ``), a capability that does not grant the action, a write past
  the root's ceiling, a read past the Source limit, a file that changed while read, an `as`
  this endpoint does not serve, and a conditional write's refusals: an `if-match` that is stale
  (naming the current content id) or malformed, or that matches no file, a directory locked past
  the wait, and a backend that cannot compare atomically; a create-only write's refusals: an
  `if-none-match=*` on a file that already exists, a value other than `*` or one sent with
  `if-match`, and a backend that cannot check and create atomically; and a create that lost to
  another writer. The spill store (`src/spill.rs`) has its own errors.
- **Acknowledgments** (`text/plain`): `wrote N bytes to <path>` for a `Sink`, `deleted <path>`
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
  `read it again`, one that changed while served says `retry`, a stale `if-match` says `read it
  again` and names the current content id, an `if-none-match=*` on a file that exists and a
  create that lost to another writer say `read it again`, a directory locked past the wait says
  `retry`, and an unsupported `as` lists the values that are served.
- No color, no terminal control codes and no markup are written.

## How it is tested

Every named check has a result: Pass, Fail or Blocked. Pass covers only the stated
assertions, not overall accessibility. The test results below come from `cargo test
--workspace` on main commit `37965dec5ffd1ccac6d7a658cb71434ebbb8de92`, on Linux,
2026-11-12 (America/Los_Angeles), with Cargo 1.99.0 and rustc 1.99.0. CI repeats these
native tests through `.github/workflows/ci.yml`; it also runs macOS tests, Windows jail
name tests and a wasm32 library lint. A build or lint is not a browser or assistive
technology evaluation. Linux does not exercise the browser backend or the tests that
require a case- or normalization-folding volume.

| Check | Result | Evidence |
|---|---|---|
| Host paths absent from selected request errors | Pass | `tests/audit_regressions.rs`: `f4_errors_never_name_the_host_path`, run by the command above. Checks a failed read, a delete and two writes; does not cover every error or spill configuration errors. |
| Canonical path spelling hint | Pass | `src/lib.rs`: `a_path_has_one_canonical_spelling`, run by the command above. Checks hints for four non-canonical paths and rejection of other invalid paths; not every path refusal. |
| Write acknowledgments | Pass | `tests/bodies.rs`, `tests/reads_body.rs` and `tests/sink_encoding.rs`, run by the command above. Assert acknowledgment bytes or their prefix for selected writes; no host presentation evaluation. |
| File changed while read | Pass | `tests/bodies.rs`, run by the command above. Asserts a conflict containing `changed while read`; does not assert all recovery wording. |
| Write ceiling refusal | Pass | `tests/max_write.rs`: `one_byte_past_the_ceiling_is_refused_with_nothing_left_behind`, run by the command above. Asserts the stated 16-byte ceiling for the tested write forms. |
| Directory listing form | Pass | `tests/listing.rs`: `a_directory_sources_as_the_newline_list_of_its_child_names`, run by the command above. Asserts sorted names, one per line, including a subdirectory, and the text media type; no assistive technology evaluation. |
| Stale conditional write refusal | Pass | `tests/if_match.rs`: `a_stale_token_is_refused_naming_the_current_one_and_changes_nothing`, run by the command above. Asserts request, current content id, `read it again`, absence of the host path and unchanged file. |
| Missing conditional write target and lock timeout | Pass | `tests/if_match.rs`: `a_missing_file_matches_no_token_and_nothing_is_created` asserts request and `does not exist`; `a_lock_held_past_the_wait_is_a_transient_refusal` asserts request and `retry`. Both run by the command above; neither asserts absence of the host path. |
| Create-only refusal and lost create | Pass | `tests/if_none_match.rs`: `an_existing_file_is_refused_naming_the_request_and_changes_nothing` and `two_unconditional_writers_creating_one_file_lose_the_race_as_conflict`, run by the command above. Assert request, `read it again` and absence of the host path for these conflicts. |
| Remaining refusal and recovery wording; delete and existence acknowledgments; endpoint description | Blocked | No complete current wording evaluation. The tests above cover selected assertions only; earlier source reading is not verification of every message. |
| No generated color, terminal control codes or markup | Blocked | No exhaustive check of output, including caller-controlled names and operating system error text, was run. |
| Rendered documentation and host presentation: keyboard, focus, contrast, zoom and reflow | Blocked | No interactive browser or terminal host evaluation was available for this update. This library supplies text; its host controls presentation. |
| Automated accessibility checker | Blocked | No axe or other automated accessibility checker was run; no rendered host was configured for this update. Rust tests do not evaluate WCAG conformance. |
| Screen reader | Blocked | No screen reader session was available; no screen reader was used on this output. |
| Screen magnifier | Blocked | No magnifier session was available; no screen magnifier was used on this output. |
| Speech input | Blocked | No speech-input session was available; no speech-input software was used on this output. |
| Switch access | Blocked | No switch-access session was available; no switch-access software was used on this output. |
| Braille display | Blocked | No braille display was available or used on this output. |

## Known limitations

These limitations were rechecked by reading the named source on the same main commit
on 2026-11-12. Fail records the described limitation, not a WCAG conformance verdict.
Source inspection does not demonstrate the experience in a host or with assistive technology.

| Check | Result | Evidence |
|---|---|---|
| Distinguish files from directories in listings | Fail | `tests/listing.rs`'s listing fixture and `src/lib.rs`: child names carry no directory indicator; a subdirectory is listed exactly as a file is. The listing test above confirms the form. |
| Unsupported verb refusal names the request in plain language | Fail | Source inspection of `src/lib.rs`: `file endpoint does not support the … verb` uses the verb's Rust spelling and omits the request. No runtime accessibility evaluation. |
| Browser storage failure gives a recovery action | Fail | Source inspection of the wasm32 backend in `src/lib.rs`: storage failures say `localStorage error`, with `(quota?)` added for writes, and give no recovery action. Browser runtime check is Blocked: no browser storage-failure session was run. |
| Temporary-name collision refusal gives a recovery action | Fail | Source inspection of `src/lib.rs` and `src/spill.rs`: `stage … temporary name collisions` and `spill: temporary name collisions` give no recovery action. No collision was induced in this review. |
| Spill configuration errors avoid host paths | Fail | Source inspection of `FileSpill::new` in `src/spill.rs`: errors include the configured spill directory's host path. This is host configuration, not a request path. No runtime failure was induced in this review. |

## Contributing

Read this file before changing any output listed above: an error's words, an acknowledgment, a
listing or the endpoint's description. Keep meaning in words, name the request a message is
about, and never the host path. In the pull request's Accessibility section, give each check a
row in a Check | Result | Evidence table: Pass, Fail or Blocked, with the test or command,
tool and version used, or why it could not run. Keep unrun checks as Blocked, including
assistive technologies nobody used. Historical runs that CI does not repeat remain Blocked
with their dates until rerun.

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
| 2026-11-03 | Listed and tested the conditional write's refusals. |
| 2026-11-08 | Listed and tested the create-only write's refusals and the lost create. |
| 2026-11-12 | Recorded scoped test results, source-reviewed limitations and explicit blocked evaluations. |

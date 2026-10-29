# Directory listing cache: measurements and correctness limits

Research for ledger #2540, 2026-10-29. No production behavior changes are proposed.
The accompanying executable is an isolated, unpublished research crate, including
deliberately unsafe caching experiments. It must not be used as a file endpoint.

**Recommendation:** retain uncached directory listings for the present contract:
an external create completed before a read must appear in that read, without
waiting for a watcher. Parent cuts are cheap and useful for an explicitly eventual
cache, but asynchronous notifications cannot establish this contract. A directory
stat is much cheaper than enumeration, but `(mtime, inode, size)` is not a reliable
version. A full listing comparison is the conservative validation baseline; it
does not avoid enumeration, and core's current revalidation does not automatically
avoid recomputing a composition over the listing.

**Incomplete measurement:** warm-cache measurements are below; genuine cold OS
cache measurements could not be obtained on this worker. This is not a completed
warm/cold performance study. macOS, Windows and NFS behavior below is a source
review, not a claim of execution on those platforms.

## Contract and reproduction

“Correct” here means no additional stale set after a completed mutation, with no
concurrent mutation during the read, on a filesystem whose local enumeration is
coherent. Neither today's enumeration nor these proposals provide an atomic
snapshot during arbitrary concurrent edits. A network filesystem can itself
return stale enumeration data; an application cache must not make that worse.
The representation is the sorted, filtered set of direct child names, not their
contents. It is capability-specific: denied names, links, unsupported names and
staging files stay out.

Baseline: ikigai-fs commit `4dddb8d9d925b5e5e6031633682818689d98b6de`.
`cargo test --test listing` passed all seven existing tests before the spike.
The new `reproduce` probe then established:

1. On a real `cacheable_space`, a separate Python process creates a file and the
   next kernel listing includes it. The unchanged listing is **not** cached.
2. An isolated wrapper changing only the listing's cache flag stores the answer.
   Create another child and cut only that child's thread: the next listing still
   omits it. This intentionally asserts the stale answer to preserve the finding
   without leaving a permanently failing test in the repository.
3. Cutting the directory's thread repairs the answer. This proves the invalidation
   target matters; it does not prove an OS event will arrive before a read.
   A real kernel Sink creating another child also leaves the unsafe listing stale.

The `revalidation` probe uses the actual released kernel, a fixed injected clock,
zero freshness, and an origin validator. For two identical reads of a composite:

| Validator | Full directory scans | New leaf bodies returned | Composite executions |
| --- | ---: | ---: | ---: |
| Directory stat tuple | 1 | 1 | 2 |
| Content hash of fresh listing | 2 | 1 | 2 |

Both conditionally reuse the stored leaf body on the second read. Neither makes
the composite execute only once. The hash variant has already materialized the
new listing to compute the hash, even when it returns “revalidated”. The stat
variant is deliberately a performance/behavior spike, with none of the complete
re-admission and race defenses a real implementation needs.

Raw observations and reproducible programs are linked below.

## Measurements on this machine

Linux `7.2.6-76070206-generic`, x86-64, ext4 on `/dev/mapper/data-root`, Intel
Core i7-11800H, 16 logical CPUs; rustc `1.99.0 (b940084d7 2026-09-28)`.
Release build; ikigai-core **0.2.7**, notify **8.2.1**, rustix 1.1.6. The
application's manifest still permits core 0.2.3; the research crate pins 0.2.7.
No dependency version in the application was changed.

Fixtures contain 10, 1,000 or 100,000 one-byte regular files with fixed ASCII names
`file-000000.rq`, etc. Each directory sits below a root with only that directory,
so this does not model expensive canonical spelling scans through large ancestor
directories. Fixture creation, initial verification and five warmups precede
timing. There are 501 samples for the two smaller sizes and 51 for the largest.
Results include allocation/deallocation, sorting and answer copying as applicable.
Operations run in separate batches on a shared machine, without CPU affinity;
small differences between batches are noise, not evidence of a speedup.

Median microseconds (p95 estimate in parentheses):

| Operation, warm OS cache | 10 children | 1,000 children | 100,000 children |
| --- | ---: | ---: | ---: |
| Path `stat` (`std::fs::metadata`) | 0.725 (0.757) | 0.396 (0.414) | 0.409 (0.435) |
| `fstat` on retained directory handle | 0.385 (0.391) | 0.207 (0.211) | 0.213 (0.221) |
| Enumerate names + sort, without endpoint filters | 6.480 (6.714) | 215.174 (223.892) | 25,648.812 (26,032.479) |
| Actual endpoint listing, including jail and filtering | 10.426 (13.633) | 300.952 (318.285) | 34,269.135 (36,050.775) |
| Actual endpoint listing + `ContentId::of` | 10.379 (11.212) | 310.502 (321.210) | 34,160.160 (35,421.342) |
| Hash already-held listing bytes only | 0.144 (0.145) | 3.158 (3.177) | 164.266 (166.190) |
| Actual kernel, current uncached listing | 11.461 (12.756) | 301.966 (310.677) | 34,829.626 (35,694.370) |
| Kernel hit on deliberately frozen listing | 0.804 (0.937) | 0.946 (1.006) | 54.045 (55.534) |

The frozen listing is an unsafe best-case cost reference, not a candidate that
passes correctness. Stat's ~0.4 microseconds at 100,000 entries is promising
against ~34 milliseconds to enumerate. It is only the validation syscall cost:
a real endpoint still needs capability/path re-admission, directory identity
checks and answer copying. A retained handle alone does not prove that the path
still names that directory. Hashing the held ~1.5 MB listing costs ~0.16 ms;
the expensive part of the hash baseline is reading, filtering and sorting it.

| Cold OS cache | 10 | 1,000 | 100,000 |
| --- | --- | --- | --- |
| Stat, listing, hash baseline | Not measured | Not measured | Not measured |

The worker has no noninteractive sudo access. Global `drop_caches` was not run.
`POSIX_FADV_DONTNEED` on a directory descriptor was accepted, but that does not
establish eviction of ext4 directory blocks, dentries or inode metadata. A new
process is not a cold filesystem cache either. Neither is reported as “cold”.
To finish: on an isolated privileged machine, evict page and metadata caches
before **each** timed operation, outside its timer, independently for each
operation and size; retain the same fixture and collect distributions. Prefer
an independently mountable fixture filesystem to disturbing a shared host.
Report filesystem/mount/storage details and separate cold misses from warm
repeats; do not compare one cold stat with a listing it has just warmed.

## 1. Watcher cuts the parent

For an ordinary create/remove, invalidate the changed path and its immediate
parent's listing. For a cross-directory rename, invalidate both parents and
both names, without depending on successful rename pairing. Direct listings do
not change when a grandchild is added, so cutting every ancestor adds false
invalidations. Creating missing directories along a Sink path changes each
parent in the newly created chain. Renaming/removing a directory also invalidates
cached paths below it: parent cuts alone do not evict `old/subdirectory`.

The Linux notify probe observed `Create(File)`, `Remove(File)`, and a cross-directory
rename delivered as **From, To, and Both**, with two paths in Both and matching
trackers. Handling each emitted record literally can cut the same parents twice.
In-place writes produced data-modification and access events, with no namespace
change. Ignore access events and deduplicate parents per batch. Do not infer
“one edit = one event”.

| Platform/backend | What the consumer must handle |
| --- | --- |
| Linux / inotify | A watched directory's events carry child names; rename halves have a cookie, but may be split across reads or missing outside the watched tree. notify can emit From/To/Both. Identical pending events can coalesce; overflow requires abandoning assumed completeness. Watches are per directory, so installing watches on new subtrees races with mutations. Remote NFS edits need not generate local events. |
| macOS / FSEvents | notify's precise mode uses file paths and item flags. `ItemRenamed` becomes `RenameMode::Any`: there is no old/new association to rely on. A directory/coalesced event is not a single named child mutation. `MustScanSubDirs` requires subtree recovery; dropped-event flags and root changes require broad invalidation/re-establishing the watch. |
| Windows / ReadDirectoryChangesW | Native records name changes relative to the watched directory, optionally recursively. notify emits separate From and To events, not a guaranteed paired Both. Buffer overflow discards details; a zero-byte completion or `ERROR_NOTIFY_ENUM_DIR` requires enumeration/recovery. No next-request ordering guarantee follows from asynchronous delivery. |

These OS facts come from [inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html),
[Apple's event handling guide](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/UsingtheFSEventsFramework/UsingtheFSEventsFramework.html),
and [ReadDirectoryChangesW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw).
Translations were checked in notify 8.2.1's
[inotify](https://github.com/notify-rs/notify/blob/7f6995de25f07bf28ab513c64375d94b4ccd08a1/notify/src/inotify.rs),
[FSEvents](https://github.com/notify-rs/notify/blob/7f6995de25f07bf28ab513c64375d94b4ccd08a1/notify/src/fsevent.rs), and
[Windows](https://github.com/notify-rs/notify/blob/7f6995de25f07bf28ab513c64375d94b4ccd08a1/notify/src/windows.rs)
sources. In particular, do not assume Windows overflow always becomes
`need_rescan()`: that version's Windows callback ignores its byte-count parameter
and logs/unwatches on unrecognized error codes. That recovery path needs native
testing before relying on this backend for cache correctness.

The existing host was also checked, at ikigai-cli commit
`57c54a10937352e7a0d9576cbf732222ee84252a`:
[`react_to_file_event`](https://github.com/ikigai-rs/ikigai-cli/blob/57c54a10937352e7a0d9576cbf732222ee84252a/crates/ikigai-embedded/src/lib.rs#L6506)
cuts named paths, skips access events, and on `need_rescan()` cuts all cached file
threads. Thus it already has broad overflow recovery for recognized rescan
events. It does not cut normal events' parents, and its watcher callback ignores
errors. It lives in the host, not this file endpoint.

**Guarantee:** once the relevant event has been processed, the dependent listing
can be recomputed. A missed event without recovery can leave it stale indefinitely;
a delayed event leaves it stale until delivery. Starting the watcher before filling
the cache, recovery on overflow/error, and cut-generation checks during cache
insertion are necessary but do not make callback delivery synchronous with an
external program's completed write. Polling or a positive TTL merely bounds some
staleness. They do not meet the next-read contract.

### Churn and invalidation cost

The churn probe performs 1,000 in-place writes distributed over `min(N, 1000)`
files, first without a watch and then with one nonrecursive notify watch. It
collects queued events after writes finish. This measures event volume, not a
controlled watcher-overhead difference: cache warming and writeback affect the
two batches. See [raw results](directory-listing-results/churn.csv). The key
observation is that none of these writes generated a structural event. A
structural-only parent policy causes zero listing cuts for this workload; cutting
the parent on every data event would needlessly invalidate it thousands of times.
Editors that save by staging and renaming do produce namespace events, even if
the final set of visible names is unchanged.

Separately, 31 samples of one real `Kernel::cut` with 1, 100 and 1,000 cached
dependents had median costs of **94, 125 and 253 ns**, respectively (p95 estimates
107, 152 and 517 ns). These are generation bumps without listeners; they do not
include a watcher callback, a cache scan for overflow recovery, or recomputation.
With matching cut listeners, core additionally enumerates affected dependents.
The expensive part is the next read: approximately 34 ms per full listing at
100,000 children here, plus whatever compositions are invalidated. At R reads
per second that each follow a cut, listing CPU demand alone is roughly
`R * 0.034` CPU-seconds/second; that is a projection from the measured cost, not
a throughput result. Cutting all ancestors spreads that cost to unrelated maps.

## 2. Sink cuts its parent too

An endpoint knows whether it created a new name, removed one, created missing
parents, or merely replaced an existing file. Synchronous extra cuts before
returning a kernel write could close that write's gap. They cannot cover other
programs, so this candidate alone fails the external-create test.

Core 0.2.7 has no direct endpoint API for additional write cuts.
`Invocation::depends_on` and `Representation::depends_on` add **read dependencies**;
they are not mutation effects. The kernel cuts the canonical target of an invoked
mutating request, including an invocation that failed after possibly changing
state. An endpoint can issue `urn:kernel:cut` only with the caller's explicit
kernel-cut capability; requiring that broad grant for an ordinary file write is
not a transparent or acceptable substitute.

Applying the “does it belong in core” test: path ancestry, staging filenames,
filesystem event interpretation and deciding whether the visible child set
changed belong in the endpoint/host. The reusable core concept would be an
invocation declaring additional affected resource threads, useful also to a store
write affecting an index/query resource. This research does not justify adding
filesystem-specific parent logic to the kernel, or an unrestricted endpoint
reference to the whole kernel. The referenced field guide is not present in
this checkout; this is the architectural assessment, not a quotation from it.

If a generic effect seam is proposed later, specify authority/namespace bounds,
canonical names, deduplication and sequencing in core. Preserve effects on a
failed/partially applied write even if there is no successful representation,
and preserve the lost-cut rule for a concurrent read. Ordinary overwrite should
not cut every ancestor. Sink stages and atomically publishes, so raw OS events
can be more conservative than the logical effect; a full listing hash can avoid
claiming changed names when only excluded staging files changed.

## 3. Stat validator through revalidation

On POSIX, adding/removing a directory entry changes directory mtime. Changing a
child's contents in place need not change its parent's mtime, which is appropriate
for this representation. This was verified locally. Directory size is allocation
metadata, not a count of children, and equal-length rename commonly preserves it.
[Linux inode semantics](https://man7.org/linux/man-pages/man7/inode.7.html)
describe the timestamp updates.

The stamp probe found **0 natural nanosecond tuple collisions in 10,000 renames**
on this ext4/kernel combination, but **10,000 collisions when truncated to seconds**.
That is not proof for other filesystems or kernels.
[Linux's multigrain timestamp design](https://kernel.org/doc/html/v7.0-rc5/filesystems/multigrain-ts.html)
explains why timestamp queries can improve resolution compared with older coarse
updates; nominal nanosecond fields alone are not a guarantee of distinct versions.

There is also a deterministic local counterexample: rename `a` to `b`, then
restore the directory's original mtime using `utime`, as a restore tool can do.
The directory's **device, inode, full nanosecond mtime and size all remain equal**,
while its set of names differs. Adding device identity is prudent but does not
repair this counterexample. Adding ctime would detect this particular restoration;
it is an improvement, not a portable monotonic change sequence. Coarse clocks,
filesystem-specific semantics and network attribute caches still need treatment.

Other limits:

- **NFS/network mounts:** stat can return an attribute-cache hit rather than a
  server check; Linux's default directory attribute lifetimes span 30–60 seconds.
  Readdir and lookup have caches too. NFSv4 change attributes may be better than
  timestamps if the server implements them correctly, but ordinary portable stat
  does not expose an authoritative change token. Unsupported/uncertain mounts
  must fall back to fresh enumeration, preserving the underlying filesystem's
  visibility limits. See [NFS cache coherence](https://man7.org/linux/man-pages/man5/nfs.5.html)
  and [notify's network caveat](https://docs.rs/notify/8.2.1/notify/#network-filesystems).
- **Windows/NTFS:** do not equate a 100 ns FILETIME representation with a unique
  directory change counter. Windows permits setting times and documents delayed
  timestamp visibility until relevant handles close; its directory-time API
  explicitly warns of values not being continuously updated. This is insufficient
  to certify the POSIX stamp scheme on NTFS. Native create/delete/rename tests
  must use directory-handle identity and last-write time, not a parent's duplicated
  directory-entry timestamp. No Windows measurements were made. See
  [File Times](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times)
  and [Directory.GetLastWriteTime](https://learn.microsoft.com/en-us/dotnet/api/system.io.directory.getlastwritetime).
  The current crate's Windows backend refuses filesystem operations anyway.
- **Browser localStorage:** there is no directory inode, mtime, or stat. The current
  browser backend explicitly reports `is_dir() == false` and offers no listing.
  A future prefix-listing backend needs its own revision protocol or a fresh key
  scan; a per-directory revision works only if every writer participates. Native
  watcher/stat conclusions do not transfer to arbitrary direct storage writes.
- **Admission/races:** revalidation must recheck the jail, capability and path's
  current directory identity before accepting a cached body. A scan and its stamp
  must describe the same version: use before/after checks, retry/fail or decline
  caching when unstable. An unchanged retained descriptor cannot authenticate a
  replaced path. Errors must never turn into “still valid”.

Any **positive freshness interval** knowingly allows external changes to remain
invisible until expiry. Zero freshness avoids that interval, but relies on a sound
validator. The tuple is not sound in the general case above. A timestamp settling
window can conservatively force rescans for recent/coarse stamps, but does not
fix restored timestamps or cached remote attributes.

This candidate uses #2534's `Invocation::stale`, `validated_by` and `revalidated`
seams. They already exist in the measured core 0.2.7; no unmerged core checkout
was needed. Zero-freshness storage is also present there (core's tests reference
#2553). A future implementation must declare the true minimum core version for
those APIs; this note makes no claim that the existing 0.2.3 minimum has them.

## 4. Hash of the canonical listing

Enumerate, apply the current jail/name/type/capability filters, sort, serialize
and hash the resulting bytes on every validation. A hash of unsorted raw entries
is the wrong validator. Names must be compared in the same capability and media
type context as the cached representation. If the digest is unchanged, return
“revalidated”; otherwise replace the body. Exact byte comparison of a retained
listing avoids even the cryptographic hash-collision assumption if “never” is
literal.

This gives the same filesystem observation as a new listing and avoids trusting
timestamps or notifications, provided it runs on **every relevant read**, including
requests served through compositions. It remains O(N) enumeration and sorting
in the implementation measured here, plus a cheap linear digest. It can avoid
downstream work only with an additional dependency/content reuse mechanism:
the zero-freshness experiment proved that #2534 alone still reruns the composite.
The existing kernel test
[`a_cacheable_composite_over_a_revalidated_answer_recomputes_and_finds_it_revalidated`](https://github.com/ikigai-rs/ikigai-core/blob/258213a653bfee6d406b1cfc3894a86a9b04d2c3/crates/ikigai-core/tests/revalidation.rs)
agrees. Do not sell the hash baseline as “no downstream recompute” today.

## Decision and follow-up acceptance tests

| Candidate | Strict next external read | Cheap unchanged directory | Reuses unchanged composition with current core |
| --- | --- | --- | --- |
| Watcher parent cuts | No: asynchronous/missing events | Yes, between delivered invalidations | Yes, until cut; stale during the gap |
| Synchronous Sink parent effects | Kernel writes only | Yes | Yes, until cut; requires an additional seam/host wrapper |
| Stat + zero freshness | Not across the demonstrated failure cases | Potentially; actual safe endpoint cost unmeasured | No, in the measured experiment |
| Full listing hash/byte comparison each read | Same observation as fresh enumeration | No: still reads entries | No, without further dependency reuse |

For today's strict contract, **do not enable listing caching on the evidence
available**. If the product chooses an explicit eventual-consistency mode, immediate
parent watcher cuts plus synchronous write effects are the lowest observed hot-read
cost option; prefer them to ancestor-wide cuts. It does not depend on #2534, but
requires robust watcher recovery and an accepted stale interval. This recommendation
is conditional, not a claim that event correctness was proved.

If strict correctness and reduced downstream work are both required, first
investigate generic dependency revalidation/content reuse: validate the listing
by a fresh enumeration, compare canonical content, and reuse a composite only
when all of its effective dependencies remain equivalent. That builds on #2534
but needs more than its endpoint-body refresh. A platform-specific authoritative
change sequence or synchronous writer-coordination protocol might avoid the scan;
neither is supplied by portable stat or notify. Sole-writer/revision schemes can
be exact only after explicitly excluding uncoordinated writers, which changes
the contract in the question.

Before any fix, add tests that fail under the proposed unsafe cache, then require:

1. A separate process creates a child after the initial read; the very next direct
   **and composed** listing includes it. Hold watcher processing behind a barrier
   to make the delivery race deterministic; no sleep-until-event assertion can
   stand in for this test under the strict contract.
2. Repeated unchanged reads reuse the stored listing body, with counters proving
   the claimed reduction in enumeration and composition. For a validating cache,
   distinguish a fresh hit, conditional reuse and an endpoint recomputation;
   `is_cached` alone is not sufficient for zero-freshness entries.
3. External remove, same-/cross-directory rename, moves into/out of the watched
   root, replacement of a directory, and recursive directory rename/delete.
   Test both parents and old descendants, including separately delivered rename
   halves and From/To/Both/Any forms.
4. A mutation while a listing is being computed cannot file a stale cached answer
   after its cut; watch initialization, coalescing, overflow, callback error and
   lost-watch recovery fail closed. Reconcile all affected cached subtrees, not
   merely the ancestor named by a coalesced event.
5. Two changes in one coarse timestamp tick, restored mtime with equal directory
   size, inode/path replacement and simulated stale network attributes cannot
   validate changed names. In-place writes need not alter the listing; atomic
   saves may trigger safe false invalidation.
6. Scoped capabilities, changing grants, denied children, excluded staging names,
   symlinks, non-UTF-8/unsupported names, raw representation and the root listing
   preserve today's confinement and serialization rules. Test failed/partial
   kernel writes and auto-created parent chains if write effects are added.
7. Keep unsupported backends uncached/refused until native Windows/NTFS and any
   browser-directory implementation have equivalent tests. Finish the missing
   cold measurements independently of noisy CI timing.

## Reproducing the research

From the repository root, with Python 3 and Rust installed:

```sh
cargo test --test listing
cargo build --release --manifest-path docs/research/listing-cache-probe/Cargo.toml
mkdir -p target
docs/research/listing-cache-probe/target/release/listing-cache-probe reproduce target/research-reproduce
docs/research/listing-cache-probe/target/release/listing-cache-probe revalidation target/research-revalidate
python3 docs/research/listing-stamp-probe.py target/research-stamp
docs/research/listing-cache-probe/target/release/listing-cache-probe bench target/research-bench
docs/research/listing-cache-probe/target/release/listing-cache-probe fanout
docs/research/listing-cache-probe/target/release/listing-cache-probe events target/research-events
docs/research/listing-cache-probe/target/release/listing-cache-probe churn target/research-churn
```

Use fresh scratch paths; successful runs remove their own fixtures. The harness
does not evict OS caches. Benchmarks are observations, with no CI timing thresholds.
The isolated probes were checked locally with formatting, strict clippy and the
correctness commands above. Existing CI checks the unchanged library on its
supported targets; it does not execute this isolated research crate. CI cannot
certify the probe results, cross-platform event delivery or the missing cold data.

Raw files: [warm timings](directory-listing-results/warm.csv),
[cut timings](directory-listing-results/fanout.csv),
[churn](directory-listing-results/churn.csv),
[notify events](directory-listing-results/events.txt),
[stamp collisions](directory-listing-results/stamps.txt),
[cache reproduction](directory-listing-results/reproduction.txt),
[revalidation](directory-listing-results/revalidation.txt).
The CSV timing samples are nanoseconds; p95 uses the lower order statistic
`floor((samples - 1) * 0.95)`. Fixture preparation and cleanup are outside timers.

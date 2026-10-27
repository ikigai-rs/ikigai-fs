//! The file-backed **spill facility** (ledger #2241, part of the streams arc, ledger
//! #2228): [`FileSpill`], what a native host installs with
//! [`Kernel::with_spill`](ikigai_core::Kernel::with_spill) so `urn:stream:spill` writes a
//! one-shot body to a file and answers it as a body that can be read again.
//!
//! Every spill file is created relative to one open handle on the host's directory, the
//! way a `Sink` stages its write: exclusively (`O_EXCL | O_NOFOLLOW | O_CLOEXEC`), owner
//! only (mode `0600`), under a random name with the prefix [`SPILL_PREFIX`]. Its readers
//! read the descriptor the write produced, never the name again, and the file is removed
//! when the last holder of the answer lets it go.

use std::future::poll_fn;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use futures_core::Stream;
use ikigai_core::{ByteStream, Bytes, ContentHasher, ContentId, Error, Replay, Result, Spill};
use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

/// The prefix of every spill file's name: `.ikigai-spill-` and 32 random hex digits.
/// [`FileSpill::new`] removes the files with it that a killed process left behind.
pub const SPILL_PREFIX: &str = ".ikigai-spill-";

/// The largest chunk a spill reader yields.
const CHUNK: u64 = 64 * 1024;

/// A file-backed [`Spill`] facility over a directory **the host supplies** (from its
/// config home, for instance). This crate never reads an environment variable such as
/// `TMPDIR` and never picks a directory itself.
///
/// ```no_run
/// use std::sync::Arc;
/// use ikigai_core::{EndpointSpace, Kernel};
/// use ikigai_fs::FileSpill;
///
/// # fn main() -> ikigai_core::Result<()> {
/// let spill = FileSpill::new("/home/me/.config/ikigai/spill")?;
/// let kernel = Kernel::new(Arc::new(EndpointSpace::new())).with_spill(Arc::new(spill));
/// // A caller holding `urn:cap:stream:spill:<bytes>` may now spill up to that many bytes.
/// # Ok(())
/// # }
/// ```
///
/// A spill reads the body chunk by chunk, writing each chunk to a fresh file and hashing
/// it as it goes. Past `max_bytes` it stops reading, removes the file and answers
/// [`Error::OverBudget`], never a shorter body; a body that ends with an error removes
/// the file and answers that error. The answer is a seekable [`Replay`] whose
/// [`len_hint`](Replay::len_hint) is the byte count and whose
/// [`validator`](Replay::validator) is the bytes' [`ContentId`]. The file is never
/// written again, and is deleted when the last holder of the answer drops it; a reader
/// still open then keeps its own descriptor and finishes (an unlinked file lives on
/// while it is open).
///
/// **One directory, one process.** [`FileSpill::new`] removes every file in its
/// directory named with [`SPILL_PREFIX`] (only those, never anything else), on the
/// premise that they are orphans a killed process left behind. Two processes (or two
/// `FileSpill`s) sharing one spill directory would remove each other's live files, so
/// a host gives each its own directory.
///
/// Unix only: the `wasm32` backend has no file system and installs no facility, so
/// `urn:stream:spill` there answers `Unsupported`.
pub struct FileSpill {
    dir: Arc<OwnedFd>,
}

impl std::fmt::Debug for FileSpill {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSpill").finish_non_exhaustive()
    }
}

impl FileSpill {
    /// A facility spilling into `dir`, which must already exist (it is never created).
    /// The directory is opened once, following links in its own path (host
    /// configuration, not caller input), and every spill file is created relative to
    /// that handle. Removes the orphans with [`SPILL_PREFIX`] a killed process left
    /// there, and nothing else.
    pub fn new(dir: impl AsRef<Path>) -> Result<Self> {
        let path = dir.as_ref();
        let dir = rfs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            Error::Endpoint(format!(
                "open the spill directory `{}`: {e}",
                path.display()
            ))
        })?;
        remove_orphans(&dir).map_err(|e| {
            Error::Endpoint(format!(
                "remove orphaned spill files in `{}`: {e}",
                path.display()
            ))
        })?;
        Ok(FileSpill { dir: Arc::new(dir) })
    }
}

/// Remove every regular file named with [`SPILL_PREFIX`] in `dir`: what a killed
/// process left behind. A name that is not a regular file is left alone, as is every
/// other name.
fn remove_orphans(dir: &OwnedFd) -> rustix::io::Result<()> {
    let mut orphans = Vec::new();
    for entry in rfs::Dir::read_from(dir)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if name.starts_with(SPILL_PREFIX) {
            orphans.push(name.to_string());
        }
    }
    for name in orphans {
        match rfs::statat(dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile => {}
            Ok(_) | Err(Errno::NOENT) => continue,
            Err(e) => return Err(e),
        }
        match rfs::unlinkat(dir, name.as_str(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// A spill file and the name it has in the spill directory, removed on drop: while it is
/// written (so every early return removes it) and, once written, by the last holder of
/// the answer.
struct SpillFile {
    dir: Arc<OwnedFd>,
    name: String,
    file: std::fs::File,
}

impl SpillFile {
    fn create(dir: Arc<OwnedFd>) -> Result<Self> {
        for _ in 0..16 {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random)
                .map_err(|_| Error::Endpoint("spill: randomness unavailable".into()))?;
            let name = format!("{SPILL_PREFIX}{:032x}", u128::from_ne_bytes(random));
            match rfs::openat(
                &*dir,
                name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => {
                    return Ok(SpillFile {
                        dir,
                        name,
                        file: fd.into(),
                    })
                }
                Err(Errno::EXIST) => continue,
                Err(e) => return Err(Error::Endpoint(format!("spill: create a file: {e}"))),
            }
        }
        Err(Error::Endpoint("spill: temporary name collisions".into()))
    }
}

impl Drop for SpillFile {
    fn drop(&mut self) {
        let _ = rfs::unlinkat(&*self.dir, self.name.as_str(), AtFlags::empty());
    }
}

#[async_trait]
impl Spill for FileSpill {
    async fn spill(&self, mut body: ByteStream, max_bytes: u64) -> Result<Arc<dyn Replay>> {
        let mut spilled = SpillFile::create(self.dir.clone())?;
        let (mut hasher, mut len) = (ContentHasher::new(), 0u64);
        while let Some(chunk) = poll_fn(|cx| body.as_mut().poll_next(cx)).await {
            // An error of the body's own ends the spill with it; the file goes with
            // `spilled`.
            let chunk = chunk?;
            let total = len + chunk.len() as u64;
            if total > max_bytes {
                return Err(Error::OverBudget {
                    detail: format!(
                        "the body is past the spill limit of {max_bytes} bytes; nothing was kept"
                    ),
                });
            }
            spilled
                .file
                .write_all(&chunk)
                .map_err(|e| Error::Endpoint(format!("spill: write: {e}")))?;
            hasher.update(&chunk);
            len = total;
        }
        Ok(Arc::new(SpillReplay {
            file: spilled,
            len,
            id: hasher.finish(),
        }))
    }
}

/// A written spill file as a [`Replay`]: its length and content id, and the file, which
/// is removed when this is dropped.
struct SpillReplay {
    file: SpillFile,
    len: u64,
    id: ContentId,
}

impl SpillReplay {
    /// A reader from `offset` on its own duplicate of the written descriptor, so it
    /// outlives this answer (and the file's name) if it has to.
    fn reader(&self, offset: u64) -> SpillReader {
        let fd = OwnedFd::from(match self.file.file.try_clone() {
            Ok(file) => file,
            Err(e) => {
                return SpillReader {
                    fd: None,
                    at: 0,
                    end: 0,
                    failed: Some(Error::Endpoint(format!("spill: open a reader: {e}"))),
                }
            }
        });
        SpillReader {
            fd: Some(fd),
            at: offset.min(self.len),
            end: self.len,
            failed: None,
        }
    }
}

impl Replay for SpillReplay {
    fn open(&self) -> ByteStream {
        Box::pin(self.reader(0))
    }

    /// A reader from byte `offset`; past the end it yields nothing.
    fn open_at(&self, offset: u64) -> Option<ByteStream> {
        Some(Box::pin(self.reader(offset)))
    }

    fn len_hint(&self) -> Option<u64> {
        Some(self.len)
    }

    fn validator(&self) -> Option<ContentId> {
        Some(self.id)
    }
}

/// One reader of a [`SpillReplay`]: positioned reads (`pread`) on its own descriptor,
/// from `at` to `end`, in chunks of at most [`CHUNK`] bytes, each poll one bounded
/// blocking read on the polling thread, as the crate does all of its file I/O.
struct SpillReader {
    /// `None` once the stream ended.
    fd: Option<OwnedFd>,
    at: u64,
    end: u64,
    failed: Option<Error>,
}

impl SpillReader {
    fn next_chunk(&mut self) -> Option<Result<Bytes>> {
        if let Some(error) = self.failed.take() {
            return Some(Err(error));
        }
        let fd = self.fd.as_ref()?;
        if self.at >= self.end {
            self.fd = None;
            return None;
        }
        let mut buf = vec![0u8; (self.end - self.at).min(CHUNK) as usize];
        let read = loop {
            match rustix::io::pread(fd, &mut buf, self.at) {
                Err(Errno::INTR) => continue,
                other => break other,
            }
        };
        match read {
            Ok(0) => {
                self.fd = None;
                Some(Err(Error::Conflict(
                    "a spill file is shorter than was written".into(),
                )))
            }
            Ok(n) => {
                self.at += n as u64;
                buf.truncate(n);
                Some(Ok(buf.into()))
            }
            Err(e) => {
                self.fd = None;
                Some(Err(Error::Endpoint(format!("spill: read: {e}"))))
            }
        }
    }
}

impl Stream for SpillReader {
    type Item = Result<Bytes>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Ready(self.get_mut().next_chunk())
    }
}

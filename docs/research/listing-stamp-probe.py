#!/usr/bin/env python3
"""POSIX directory stamp experiments. Run with a fresh path inside the checkout."""
import json
import os
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=False)


def stamp():
    s = root.stat()
    return (s.st_dev, s.st_ino, s.st_mtime_ns, s.st_size)


try:
    a, b = root / "a", root / "b"
    a.write_text("x")
    before = stamp()
    a.write_text("in-place rewrite")
    assert stamp() == before
    print("PASS in-place content write leaves directory stamp unchanged (correct for names)")

    # Equal-length rename, then restore mtime as a backup/restore tool can do.
    atime = root.stat().st_atime_ns
    a.rename(b)
    os.utime(root, ns=(atime, before[2]))
    after = stamp()
    assert before == after, (before, after)
    assert sorted(p.name for p in root.iterdir()) == ["b"]
    print("PASS tuple collision: names changed a -> b, (dev,ino,mtime_ns,size) identical")
    print(json.dumps({"before": before, "after": after}))

    exact_collisions = coarse_collisions = 0
    for _ in range(10_000):
        before = stamp()
        os.rename(b, a)
        after = stamp()
        exact_collisions += before == after
        coarse_collisions += (before[:2] + (before[2] // 1_000_000_000, before[3])) == (
            after[:2] + (after[2] // 1_000_000_000, after[3]))
        a, b = b, a
    print(json.dumps({"rename_trials": 10_000, "natural_nanosecond_collisions": exact_collisions,
                      "collisions_if_seconds_only": coarse_collisions}))

    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
            print("directory fadvise accepted; does NOT prove dentries/inodes/block cache evicted")
        finally:
            os.close(fd)
    except OSError as e:
        print(f"directory fadvise unavailable: {e}")
finally:
    shutil.rmtree(root)

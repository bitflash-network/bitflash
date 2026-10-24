#!/usr/bin/env python3
# Copyright (c) 2026 Bitflash developers
# Distributed under the MIT/X11 software license.
"""Pack a release directory into a .tar.gz or .zip that comes out the same,
byte for byte, every time the same files go in.

tar and zip record what has nothing to do with the files: when each was
written, who owned it, the order the filesystem listed them in, and (gzip) when
the archive itself was made. Two builds of the same commit then give packages
with different hashes, and nobody can check a published package against their
own build. Here every entry is sorted by name, every time is SOURCE_DATE_EPOCH
(the commit's time when unset), owners are 0, and gzip carries no time and no
name. Permission bits are kept: the executable bit is what makes a Linux or
macOS binary run.

    reproducible-archive.py tar.gz OUT.tar.gz DIR
    reproducible-archive.py zip    OUT.zip    DIR
"""
import gzip
import os
import stat
import subprocess
import sys
import tarfile
import time
import zipfile


def source_date_epoch():
    env = os.environ.get("SOURCE_DATE_EPOCH")
    if env:
        return int(env)
    try:
        out = subprocess.check_output(["git", "log", "-1", "--format=%ct"], stderr=subprocess.DEVNULL)
        return int(out.strip())
    except Exception:
        sys.exit("SOURCE_DATE_EPOCH is not set and git cannot say when the commit was made")


def entries(root):
    """(path relative to root's parent, full path) for root and everything in
    it, sorted so every system lists them alike."""
    base = os.path.dirname(os.path.abspath(root))
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            out.append((os.path.relpath(full, base).replace(os.sep, "/"), full))
    out.append((os.path.relpath(os.path.abspath(root), base).replace(os.sep, "/"), os.path.abspath(root)))
    out.sort()
    return out


def mode_of(full):
    st = os.lstat(full)
    if stat.S_ISDIR(st.st_mode):
        return 0o755
    # Only the executable bit is a fact about the file; the rest is umask.
    return 0o755 if st.st_mode & 0o111 else 0o644


def make_tar(out, root, epoch):
    with open(out, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for name, full in entries(root):
                    info = tar.gettarinfo(full, arcname=name)
                    info.mtime = epoch
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.pax_headers = {}
                    if info.isfile():
                        info.mode = mode_of(full)
                        with open(full, "rb") as f:
                            tar.addfile(info, f)
                    else:
                        if info.isdir():
                            info.mode = 0o755
                        tar.addfile(info)


def make_zip(out, root, epoch):
    # zip stores local time with two-second steps, and nothing before 1980.
    t = time.gmtime(max(epoch, 315532800))
    date_time = (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec - t.tm_sec % 2)
    with zipfile.ZipFile(out, "w") as z:
        for name, full in entries(root):
            isdir = os.path.isdir(full)
            info = zipfile.ZipInfo(name + ("/" if isdir else ""), date_time=date_time)
            info.create_system = 3   # Unix, so the permission bits below are read
            info.external_attr = ((stat.S_IFDIR if isdir else stat.S_IFREG) | mode_of(full)) << 16
            if isdir:
                info.external_attr |= 0x10   # MS-DOS directory flag
                z.writestr(info, b"")
            else:
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(full, "rb") as f:
                    z.writestr(info, f.read(), compresslevel=9)


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("tar.gz", "zip"):
        sys.exit(__doc__)
    kind, out, root = sys.argv[1:]
    if not os.path.isdir(root):
        sys.exit("not a directory: " + root)
    epoch = source_date_epoch()
    if os.path.exists(out):
        os.remove(out)
    (make_tar if kind == "tar.gz" else make_zip)(out, root, epoch)
    print("Packed %s (%d entries, time %d)" % (out, len(entries(root)), epoch))


if __name__ == "__main__":
    main()

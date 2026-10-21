#!/usr/bin/env python3
"""
Magic-number + content-heuristic binary file detector.

Used by --exclude-binaries to skip non-text files while walking an
SMB/FTP share, without relying on a (necessarily incomplete) list of
file extensions or MIME types.
"""

from __future__ import annotations

_MAGIC_SIGNATURES: tuple[bytes, ...] = (
    b"MZ",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08",
    b"Rar!\x1a\x07",
    b"7z\xbc\xaf\x27\x1c",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"\x89PNG\r\n\x1a\n",
    b"GIF87a", b"GIF89a",
    b"\xff\xd8\xff",
    b"BM",
    b"RIFF",
    b"%PDF-",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    b"%!PS-Adobe",
    b"SQLite format 3\x00",
    b"\x00\x01\x00\x00\x00",
    b"OTTO",
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
)

_TAR_MAGIC_OFFSET = 257
_TAR_MAGIC = b"ustar"

_TEXT_BOMS: tuple[bytes, ...] = (
    b"\xef\xbb\xbf",
    b"\xff\xfe\x00\x00",
    b"\x00\x00\xfe\xff",
    b"\xff\xfe",
    b"\xfe\xff",
)

_TEXT_BYTES = frozenset(
    {0x09, 0x0A, 0x0B, 0x0C, 0x0D} | set(range(0x20, 0x7F))
)

_NON_TEXT_RATIO_THRESHOLD = 0.30
DEFAULT_SAMPLE_SIZE = 8192


def is_binary(data: bytes, sample_size: int = DEFAULT_SAMPLE_SIZE) -> bool:
    """Return True if *data* looks like a binary file."""
    if not data:
        return False

    sample = data[:sample_size]

    for sig in _MAGIC_SIGNATURES:
        if sample.startswith(sig):
            return True

    if sample[_TAR_MAGIC_OFFSET:_TAR_MAGIC_OFFSET + len(_TAR_MAGIC)] == _TAR_MAGIC:
        return True

    for bom in _TEXT_BOMS:
        if sample.startswith(bom):
            return False

    if b"\x00" in sample:
        return True

    if len(sample) >= 128:
        non_text = sum(1 for b in sample if b not in _TEXT_BYTES)
        if non_text / len(sample) > _NON_TEXT_RATIO_THRESHOLD:
            return True

    return False

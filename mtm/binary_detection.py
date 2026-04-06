"""Mach-O and universal binary detection."""

from __future__ import annotations

from pathlib import Path
import struct

from mtm.models import BinaryClassification

_THIN_HEADERS: dict[bytes, tuple[str, str]] = {
    b"\xfe\xed\xfa\xce": (">", "mach-o-32"),
    b"\xce\xfa\xed\xfe": ("<", "mach-o-32-swapped"),
    b"\xfe\xed\xfa\xcf": (">", "mach-o-64"),
    b"\xcf\xfa\xed\xfe": ("<", "mach-o-64-swapped"),
}

_FAT_HEADERS: dict[bytes, tuple[str, str, str]] = {
    b"\xca\xfe\xba\xbe": (">", "I", "fat-mach-o"),
    b"\xbe\xba\xfe\xca": ("<", "I", "fat-mach-o-swapped"),
    b"\xca\xfe\xba\xbf": (">", "Q", "fat-mach-o-64"),
    b"\xbf\xba\xfe\xca": ("<", "Q", "fat-mach-o-64-swapped"),
}

_KNOWN_CPU_TYPES = {
    7,  # i386
    12,  # ARM
    18,  # PowerPC
    0x01000007,  # x86_64
    0x0100000C,  # arm64
    0x01000012,  # ppc64
    0x0200000C,  # arm64_32
}


def classify_file(path: Path, file_size: int | None = None) -> BinaryClassification:
    """Classify a file by reading only its Mach-O header bytes."""

    if file_size is None:
        file_size = path.stat().st_size

    with path.open("rb") as handle:
        header = handle.read(32)

    if len(header) < 8:
        return BinaryClassification(False, False, "file-too-small")

    magic = header[:4]

    if magic in _THIN_HEADERS:
        endian, reason = _THIN_HEADERS[magic]
        cputype = struct.unpack(f"{endian}I", header[4:8])[0]
        if cputype in _KNOWN_CPU_TYPES:
            return BinaryClassification(True, False, reason)
        return BinaryClassification(False, False, "unrecognized-thin-cputype")

    if magic in _FAT_HEADERS:
        endian, size_format, reason = _FAT_HEADERS[magic]
        nfat_arch = struct.unpack(f"{endian}I", header[4:8])[0]
        arch_entry_size = 32 if size_format == "Q" else 20
        fat_header_size = 8 + (nfat_arch * arch_entry_size)
        if nfat_arch < 1 or nfat_arch > 64 or fat_header_size > file_size:
            return BinaryClassification(False, False, "invalid-fat-header")

        if len(header) < 8 + arch_entry_size:
            with path.open("rb") as handle:
                header = handle.read(8 + arch_entry_size)

        first_arch = header[8 : 8 + arch_entry_size]
        if len(first_arch) < arch_entry_size:
            return BinaryClassification(False, False, "truncated-fat-header")

        cputype = struct.unpack(f"{endian}I", first_arch[:4])[0]
        if cputype not in _KNOWN_CPU_TYPES:
            return BinaryClassification(False, False, "unrecognized-fat-cputype")

        if size_format == "Q":
            offset = struct.unpack(f"{endian}Q", first_arch[8:16])[0]
            size = struct.unpack(f"{endian}Q", first_arch[16:24])[0]
        else:
            offset = struct.unpack(f"{endian}I", first_arch[8:12])[0]
            size = struct.unpack(f"{endian}I", first_arch[12:16])[0]

        if offset == 0 or size == 0 or (offset + size) > file_size:
            return BinaryClassification(False, False, "invalid-fat-arch-range")

        return BinaryClassification(True, True, reason)

    return BinaryClassification(False, False, "non-mach-o")

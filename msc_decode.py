from __future__ import annotations

import argparse
import base64
import binascii
import json
import struct
import sys
import zlib
from pathlib import Path
from xml.etree import ElementTree as ET

# ScDecodeBinary rejects input at or above this length before allocating.
MAX_BASE64_LEN = 0xC800001

OLE_COMPOUND_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
IMAGELIST_MAGIC = b"IL"

# Valid base64 alphabet; everything else is skipped rather than rejected,
# which is what lets the embedded newlines through.
_B64_ALPHABET = set(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)


def detect_format(raw: bytes) -> str:
    """Distinguish the two .msc container formats ScLoadConsole handles."""
    if raw[:8] == OLE_COMPOUND_MAGIC:
        return "structured-storage"
    stripped = raw.lstrip()
    if stripped[:5] == b"<?xml" or stripped[:1] == b"<":
        return "xml"
    return "unknown"


def console_file_checksum(raw: bytes) -> str:
    """
    Reproduce ScGetConsoleFileChecksum: CRC-32 over the whole file, formatted
    as an unsigned decimal string (the binary uses _ultow with radix 10).

    This is the value that belongs in the user-state file's SourceChecksum
    attribute -- MMC compares it to decide whether cached view state is stale.
    """
    return str(zlib.crc32(raw) & 0xFFFFFFFF)


def _localname(tag: str) -> str:
    """Drop any XML namespace so lookups work regardless of prefixes."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def decode_base64_lenient(text: str) -> bytes:
    """
    Decode like ScDecodeBinary: characters outside the base64 alphabet are
    skipped instead of raising, and '=' terminates. Python's base64 module is
    stricter than MMC, so filter first.
    """
    data = text.encode("ascii", errors="ignore")
    if len(data) >= MAX_BASE64_LEN:
        raise ValueError(f"payload too large: {len(data)} bytes (MMC caps at {MAX_BASE64_LEN})")

    filtered = bytes(b for b in data if b in _B64_ALPHABET)
    # Trim to a whole number of quads; MMC stops at the first '=' or short group.
    filtered = filtered.split(b"=", 1)[0]
    filtered += b"=" * (-len(filtered) % 4)
    try:
        return base64.b64decode(filtered, validate=False)
    except binascii.Error as exc:
        raise ValueError(f"base64 decode failed: {exc}") from exc


def parse_imagelist(payload: bytes) -> dict | None:
    """
    Parse a comctl32 image-list stream header (ImageList_Write output).

    Layout after the 'IL' magic: version, cImage, cAlloc, cGrow, cx, cy as
    u16, then clrBk as u32 and a flags u16. The pixel data follows as a
    standard BITMAPFILEHEADER-prefixed DIB.
    """
    if payload[:2] != IMAGELIST_MAGIC or len(payload) < 20:
        return None

    version, c_image, c_alloc, c_grow, cx, cy = struct.unpack_from("<6H", payload, 2)
    clr_bk, flags = struct.unpack_from("<IH", payload, 14)

    info = {
        "version": f"0x{version:04x}",
        "cImage": c_image,
        "cAlloc": c_alloc,
        "cGrow": c_grow,
        "cx": cx,
        "cy": cy,
        "clrBk": f"0x{clr_bk:08x}",
        "flags": f"0x{flags:04x}",
    }

    bmp_offset = payload.find(b"BM", 20)
    if bmp_offset != -1:
        info["dib_offset"] = bmp_offset
        info["dib_size"] = len(payload) - bmp_offset
        # The DIB is a horizontal strip of cAlloc tiles, so its pixel width is
        # cAlloc * cx rather than cx. Read it from BITMAPINFOHEADER to be sure.
        if len(payload) >= bmp_offset + 26:
            width, height = struct.unpack_from("<ii", payload, bmp_offset + 18)
            info["strip_width"] = width
            info["strip_height"] = height
    return info


def identify(payload: bytes) -> tuple[str, dict]:
    """Classify a decoded blob and return (kind, details)."""
    il = parse_imagelist(payload)
    if il is not None:
        return "imagelist", il

    # Small blobs are snap-in view state; showing them as int32s is far more
    # readable than a hexdump.
    if len(payload) <= 64 and len(payload) >= 4:
        count = len(payload) // 4
        values = list(struct.unpack_from(f"<{count}i", payload, 0))
        return "state", {"int32": values, "trailing": len(payload) % 4}

    return "opaque", {"head": payload[:32].hex(" ")}


def collect_binaries(root: ET.Element) -> list[ET.Element]:
    """Return <Binary> children of <BinaryStorage>, in document order."""
    for elem in root.iter():
        if _localname(elem.tag) == "BinaryStorage":
            return [c for c in elem if _localname(c.tag) == "Binary"]
    return []


def collect_references(root: ET.Element) -> dict[int, list[str]]:
    """Map BinaryRefIndex -> list of element names that reference it."""
    refs: dict[int, list[str]] = {}
    for elem in root.iter():
        raw = elem.get("BinaryRefIndex")
        if raw is None:
            continue
        try:
            idx = int(raw)
        except ValueError:
            continue
        label = _localname(elem.tag)
        name = elem.get("Name")
        if name:
            label = f'{label}[Name="{name}"]'
        refs.setdefault(idx, []).append(label)
    return refs


def analyse(path: Path) -> dict:
    raw = path.read_bytes()
    fmt = detect_format(raw)

    result: dict = {
        "file": str(path),
        "size": len(raw),
        "format": fmt,
        "crc32_decimal": console_file_checksum(raw),
        "binaries": [],
    }

    if fmt == "structured-storage":
        result["note"] = (
            "Legacy OLE compound-document .msc (pre-3.0). ScOpenDocAsStructuredStorage "
            "handles these; parsing requires an OLE reader such as olefile."
        )
        return result
    if fmt != "xml":
        result["note"] = "Unrecognised container; not XML and not a compound document."
        return result

    root = ET.fromstring(raw)
    result["root_element"] = _localname(root.tag)
    result["console_version"] = root.get("ConsoleVersion")
    result["program_mode"] = root.get("ProgramMode")

    refs = collect_references(root)
    for index, node in enumerate(collect_binaries(root)):
        entry: dict = {"index": index, "name": node.get("Name"), "referenced_by": refs.get(index, [])}
        text = (node.text or "").strip()
        try:
            payload = decode_base64_lenient(text)
        except ValueError as exc:
            entry["error"] = str(exc)
            result["binaries"].append(entry)
            continue

        kind, details = identify(payload)
        entry.update(
            {
                "base64_chars": len(text),
                "decoded_bytes": len(payload),
                "kind": kind,
                "details": details,
            }
        )
        entry["_payload"] = payload  # stripped before JSON output
        result["binaries"].append(entry)

    return result


def extract(result: dict, outdir: Path) -> list[Path]:
    """Write each decoded blob to disk, plus any embedded DIB as a .bmp."""
    outdir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for entry in result["binaries"]:
        payload = entry.get("_payload")
        if payload is None:
            continue

        stem = f"{entry['index']:02d}_{entry.get('name') or entry.get('kind', 'blob')}"
        stem = "".join(c if c.isalnum() or c in "._-" else "_" for c in stem)

        blob_path = outdir / f"{stem}.bin"
        blob_path.write_bytes(payload)
        written.append(blob_path)

        # An image-list stream carries a BITMAPFILEHEADER-prefixed DIB, but
        # comctl32 leaves bfSize holding the header offset (54) instead of the
        # real length. Patch it so the extracted file is a strictly valid BMP.
        offset = entry.get("details", {}).get("dib_offset")
        if offset is not None:
            dib = bytearray(payload[offset:])
            struct.pack_into("<I", dib, 2, len(dib))
            bmp_path = outdir / f"{stem}.bmp"
            bmp_path.write_bytes(bytes(dib))
            written.append(bmp_path)

    return written


def report(result: dict) -> None:
    print(f"File          : {result['file']}")
    print(f"Size          : {result['size']:,} bytes")
    print(f"Format        : {result['format']}")
    print(f"CRC-32        : {result['crc32_decimal']}  (SourceChecksum value)")

    if "note" in result:
        print(f"\nNote: {result['note']}")
        return

    print(f"Root element  : <{result['root_element']}>")
    print(f"ConsoleVersion: {result['console_version']}")
    print(f"ProgramMode   : {result['program_mode']}")

    binaries = result["binaries"]
    if not binaries:
        print("\nNo <BinaryStorage>/<Binary> entries found.")
        return

    total = sum(b.get("decoded_bytes", 0) for b in binaries)
    print(f"\n{len(binaries)} binary payload(s), {total:,} bytes decoded\n")

    for entry in binaries:
        head = f"[{entry['index']:>2}]"
        if entry.get("error"):
            print(f"{head} ERROR: {entry['error']}")
            continue

        name = entry.get("name") or "(unnamed)"
        print(f"{head} {name}")
        print(f"     {entry['base64_chars']:,} base64 chars -> {entry['decoded_bytes']:,} bytes  [{entry['kind']}]")

        details = entry["details"]
        if entry["kind"] == "imagelist":
            print(
                f"     ImageList {details['cx']}x{details['cy']}, "
                f"cImage={details['cImage']} cAlloc={details['cAlloc']} "
                f"cGrow={details['cGrow']} flags={details['flags']}"
            )
            if "dib_offset" in details:
                strip = ""
                if "strip_width" in details:
                    strip = f", strip {details['strip_width']}x{details['strip_height']}"
                print(f"     DIB at +{details['dib_offset']} ({details['dib_size']:,} bytes{strip})")
        elif entry["kind"] == "state":
            print(f"     int32: {details['int32']}")
        else:
            print(f"     head: {details['head']}")

        if entry["referenced_by"]:
            print(f"     referenced by: {', '.join(entry['referenced_by'])}")
        else:
            print("     referenced by: (nothing -- orphaned entry)")
        print()


def hexdump(payload: bytes, width: int = 16) -> str:
    """Classic offset / hex / ASCII dump, for when readable output is wanted."""
    lines = []
    for offset in range(0, len(payload), width):
        chunk = payload[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines) + "\n"


def decode_file(infile: Path, outfile: Path, as_hex: bool = False) -> int:
    """
    Read base64 text from infile, decode it, and write the result to outfile.

    Using files rather than argv matters here: the icon payloads run to ~23,000
    characters, well past the 8,191-character command-line limit on Windows.
    """
    try:
        text = infile.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        print(f"error: cannot read {infile}: {exc}", file=sys.stderr)
        return 2

    try:
        payload = decode_base64_lenient(text.strip())
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        if as_hex:
            outfile.write_text(hexdump(payload), encoding="ascii")
        else:
            outfile.write_bytes(payload)
    except OSError as exc:
        print(f"error: cannot write {outfile}: {exc}", file=sys.stderr)
        return 2

    kind, details = identify(payload)
    print(f"{infile} -> {outfile}", file=sys.stderr)
    print(f"  {len(text.strip()):,} base64 chars -> {len(payload):,} bytes  [{kind}]", file=sys.stderr)
    if kind == "imagelist":
        strip = ""
        if "strip_width" in details:
            strip = f", strip {details['strip_width']}x{details['strip_height']}"
        print(f"  ImageList {details['cx']}x{details['cy']}, cImage={details['cImage']}{strip}", file=sys.stderr)
    elif kind == "state":
        print(f"  int32: {details['int32']}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decode binary payloads embedded in an MMC .msc console file."
    )
    parser.add_argument("msc", type=Path, nargs="?", help="path to a .msc file to analyse")
    parser.add_argument("--extract", type=Path, metavar="DIR", help="write decoded blobs to DIR")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    parser.add_argument(
        "--decode",
        nargs=2,
        type=Path,
        metavar=("IN", "OUT"),
        help="decode base64 text from IN and write the bytes to OUT",
    )
    parser.add_argument(
        "--hex",
        action="store_true",
        help="with --decode, write a readable hexdump instead of raw bytes",
    )
    args = parser.parse_args(argv)

    if args.decode:
        return decode_file(args.decode[0], args.decode[1], as_hex=args.hex)

    if args.msc is None:
        parser.error("provide a .msc file to analyse, or use --decode IN OUT")

    if not args.msc.is_file():
        print(f"error: no such file: {args.msc}", file=sys.stderr)
        return 2

    try:
        result = analyse(args.msc)
    except ET.ParseError as exc:
        print(f"error: XML parse failed: {exc}", file=sys.stderr)
        return 1

    if args.extract:
        written = extract(result, args.extract)
        print(f"Wrote {len(written)} file(s) to {args.extract}\n")

    if args.json:
        for entry in result["binaries"]:
            entry.pop("_payload", None)
        print(json.dumps(result, indent=2))
    else:
        report(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

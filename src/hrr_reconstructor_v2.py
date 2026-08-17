#!/usr/bin/env python3
"""
HRR Reconstructor V2 - Format-Aware Recovery Framework

Goals
-----
- Recursively scan *.hrr under the EXE/script root.
- Preserve original files.
- Read the original extension from "filename.ext.hrr" as a HINT.
- Detect actual embedded structures before writing recovery outputs.
- Support a broad set of formats:
    JPEG / MPO
    PNG
    TIFF / common RAW containers
    RIFF / WEBP / WAV / AVI
    ISO-BMFF / MP4 / MOV / CR3-family hint
    ZIP / DOCX / XLSX / PPTX / other ZIP-based formats
    PDF
- Extract validated JPEG previews/thumbnails from any supported container.
- For RAW/TIFF-like files, recover embedded JPEGs where possible.
- For generic unknown data, never blindly rename or reconstruct.
- Create timestamped logs and reports.
- Never overwrite *.hrr source files.
- Console remains open after completion/errors.
- No guessed cryptographic decryption.

Important
---------
The original extension is a HINT only:
    DSC_1234.NEF.hrr -> original hint = .nef

Actual recovery is based on validated byte structures.
The tool does not assume that a filename extension proves a format.

Compile:
    py -m pip install pillow pyinstaller
    pyinstaller --onefile --console --name HRR_Reconstructor_V2 hrr_reconstructor_v2.py
"""

from __future__ import annotations

import csv
import hashlib
import logging
import os
import re
import struct
import sys
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Optional

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    Image = None
    PIL_AVAILABLE = False


APP = "HRR_Reconstructor_V2"
HRR_SUFFIX = ".hrr"

HARR = b"HARR"
JPEG_SOI = b"\xFF\xD8\xFF"
JPEG_SOI_2 = b"\xFF\xD8"
JPEG_EOI = b"\xFF\xD9"
PNG_SIG = b"\x89PNG\r\n\x1a\n"
TIFF_LE = b"II*\x00"
TIFF_BE = b"MM\x00*"
RIFF = b"RIFF"
PDF = b"%PDF-"
ZIP_LOCAL = b"PK\x03\x04"

FOOTER_SIZE = 49
MIN_EMBEDDED_JPEG = 256

ROOT = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent
)

LOG_DIR = ROOT / "_HRR_Reconstructor_Logs"
REPORT_DIR = ROOT / "_HRR_Reconstructor_V2_Reports"

LOG_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{RUN_ID}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(APP)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ExtensionHint:
    source: Path
    original_name: str
    extension: str
    base_name: str


@dataclass
class JPEGObject:
    start: int
    end: int
    width: Optional[int]
    height: Optional[int]
    size: int
    kind: str
    mode: str


@dataclass
class Structure:
    kind: str
    offset: int
    end: Optional[int]
    details: str
    confidence: str


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def safe_name(value: str) -> str:
    return re.sub(
        r'[<>:"/\\|?*\x00-\x1F]',
        "_",
        value,
    ).rstrip(" .") or "recovered"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_original_extension(path: Path) -> ExtensionHint:
    """
    photo.NEF.hrr -> .nef
    photo.jpg.hrr -> .jpg
    photo.hrr     -> "" / unknown
    """
    name = path.name
    stem = name[:-len(HRR_SUFFIX)] if name.lower().endswith(HRR_SUFFIX) else name

    suffix = Path(stem).suffix.lower()

    if suffix:
        base = stem[:-len(suffix)]
    else:
        base = stem

    return ExtensionHint(
        source=path,
        original_name=stem,
        extension=suffix,
        base_name=base,
    )


def iter_hrr_files(root: Path):
    skip = {
        "_hrr_recovery_logs",
        "_hrr_reconstructor_logs",
        "_hrr_analyzer_logs",
        "_hrr_analyzer_v4_reports",
        "_hrr_analyzer_v5_reports",
        "_hrr_analyzer_v6_reports",
        "_hrr_analyzer_v7_reports",
        "_hrr_recovery_logs",
        "_hrr_recovery_output",
        "_hrr_recovered",
        "_hrr_reconstructor_v2_reports",
    }

    skip = {x.lower() for x in skip}

    for current, dirs, files in os.walk(root):
        dirs[:] = [
            d for d in dirs
            if d.lower() not in skip
        ]

        for name in files:
            if name.lower().endswith(HRR_SUFFIX):
                yield Path(current) / name


def parse_harr_footer(data: bytes) -> Optional[dict]:
    if len(data) < FOOTER_SIZE:
        return None

    for start in range(
        len(data) - FOOTER_SIZE,
        -1,
        -1,
    ):
        if data[start:start + 4] != HARR:
            continue

        footer = data[start:start + FOOTER_SIZE]

        if footer[-4:] != HARR:
            continue

        stored_offset = int.from_bytes(
            footer[33:37],
            "big",
        )

        if stored_offset != start:
            continue

        return {
            "start": start,
            "end": start + FOOTER_SIZE,
            "version": footer[4],
            "field24": footer[5:29],
            "footer_offset": stored_offset,
            "constant": int.from_bytes(
                footer[37:41],
                "big",
            ),
        }

    return None


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_magic(data: bytes) -> list[Structure]:
    found: list[Structure] = []

    if data.startswith(PNG_SIG):
        found.append(
            Structure(
                "PNG",
                0,
                None,
                "PNG signature",
                "high",
            )
        )

    if data.startswith(TIFF_LE):
        found.append(
            Structure(
                "TIFF-LE",
                0,
                None,
                "TIFF little-endian header",
                "high",
            )
        )

    if data.startswith(TIFF_BE):
        found.append(
            Structure(
                "TIFF-BE",
                0,
                None,
                "TIFF big-endian header",
                "high",
            )
        )

    if data.startswith(PDF):
        found.append(
            Structure(
                "PDF",
                0,
                None,
                "PDF header",
                "high",
            )
        )

    if data.startswith(ZIP_LOCAL):
        found.append(
            Structure(
                "ZIP",
                0,
                None,
                "ZIP local file header",
                "medium",
            )
        )

    if data.startswith(RIFF):
        if len(data) >= 12:
            form = data[8:12]
            if form == b"WEBP":
                kind = "WEBP"
            elif form == b"WAVE":
                kind = "WAV"
            elif form == b"AVI ":
                kind = "AVI"
            else:
                kind = "RIFF"
            found.append(
                Structure(
                    kind,
                    0,
                    None,
                    "RIFF container",
                    "high",
                )
            )

    # ISO-BMFF / MP4 / MOV style:
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12].decode("ascii", errors="replace")
        found.append(
            Structure(
                "ISO-BMFF",
                0,
                None,
                f"ftyp={brand}",
                "high",
            )
        )

    return found


def classify_extension_hint(ext: str) -> str:
    ext = ext.lower()

    jpeg = {".jpg", ".jpeg", ".jpe", ".jps"}
    raw = {
        ".nef", ".cr2", ".cr3", ".arw", ".dng", ".raf",
        ".orf", ".rw2", ".pef", ".srw", ".x3f", ".3fr",
        ".iiq", ".rwl", ".raw",
    }
    png = {".png"}
    tiff = {".tif", ".tiff"}
    video = {".mp4", ".mov", ".m4v", ".3gp", ".avi", ".webm"}
    office = {
        ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"
    }

    if ext in jpeg:
        return "jpeg"
    if ext in raw:
        return "raw"
    if ext in png:
        return "png"
    if ext in tiff:
        return "tiff"
    if ext in video:
        return "video"
    if ext in office:
        return "zip_based_office"
    if ext == ".pdf":
        return "pdf"

    return "unknown"


# ---------------------------------------------------------------------------
# JPEG / MPO
# ---------------------------------------------------------------------------

def jpeg_is_valid(blob: bytes) -> tuple[bool, Optional[int], Optional[int]]:
    if PIL_AVAILABLE:
        if not (
            blob.startswith(JPEG_SOI_2)
            and blob.endswith(JPEG_EOI)
        ):
            return False, None, None

        try:
            with Image.open(BytesIO(blob)) as img:
                width, height = img.size
                img.verify()

            with Image.open(BytesIO(blob)) as img:
                img.load()

            return True, width, height
        except Exception:
            return False, None, None

    return False, None, None


def find_valid_jpegs(data: bytes) -> list[JPEGObject]:
    result: list[JPEGObject] = []
    pos = 0

    while True:
        start = data.find(JPEG_SOI_2, pos)
        if start < 0:
            break

        end_marker = data.find(
            JPEG_EOI,
            start + 2,
        )

        if end_marker < 0:
            break

        end = end_marker + 2
        blob = data[start:end]

        if len(blob) >= MIN_EMBEDDED_JPEG:
            valid, width, height = jpeg_is_valid(blob)

            if valid:
                kind = (
                    "full"
                    if width >= 800 or height >= 600
                    else "thumbnail"
                )

                result.append(
                    JPEGObject(
                        start=start,
                        end=end,
                        width=width,
                        height=height,
                        size=len(blob),
                        kind=kind,
                        mode="direct",
                    )
                )

        pos = end

    return result


def reconstruct_missing_soi(region: bytes) -> list[tuple[str, bytes]]:
    """
    Very conservative:
    - only candidates ending exactly at a valid JPEG EOI
    - synthetic prefix is ONLY FF D8
    - validate candidate with Pillow before output

    Candidate starts:
    - whole region
    - known JPEG marker boundaries
    - MPF marker neighborhood
    """
    attempts: list[tuple[str, bytes]] = []

    # Candidate end points.
    eoi = []
    pos = 0

    while True:
        p = region.find(JPEG_EOI, pos)
        if p < 0:
            break
        eoi.append(p + 2)
        pos = p + 2

    if not eoi:
        return attempts

    end = eoi[-1]

    cues = set()

    # JPEG segment starts.
    for marker in (
        b"\xFF\xE0",
        b"\xFF\xE1",
        b"\xFF\xE2",
        b"\xFF\xDB",
        b"\xFF\xC0",
        b"\xFF\xC1",
        b"\xFF\xC2",
        b"\xFF\xDA",
    ):
        p = region.find(marker)
        if p >= 0:
            cues.add(p)

    mpf = region.find(b"MPF")
    if mpf >= 2:
        cues.add(mpf - 2)

    # Whole region.
    attempts.append(
        (
            "whole_region_plus_SOI",
            JPEG_SOI_2 + region[:end],
        )
    )

    for cue in sorted(cues):
        attempts.append(
            (
                f"cue_{cue}_plus_SOI",
                JPEG_SOI_2 + region[cue:end],
            )
        )

    # De-duplicate.
    unique = {}
    for label, candidate in attempts:
        unique.setdefault(sha256(candidate), (label, candidate))

    return list(unique.values())


# ---------------------------------------------------------------------------
# RAW / TIFF / EXIF support
# ---------------------------------------------------------------------------

def validate_tiff_header(data: bytes, offset: int = 0) -> Optional[Structure]:
    if offset + 8 > len(data):
        return None

    header = data[offset:offset + 8]

    if header[:2] == b"II":
        order = "<"
        endian = "LE"
    elif header[:2] == b"MM":
        order = ">"
        endian = "BE"
    else:
        return None

    magic = struct.unpack(
        order + "H",
        header[2:4],
    )[0]

    if magic not in (42, 43):
        return None

    first_ifd = struct.unpack(
        order + "I",
        header[4:8],
    )[0]

    if first_ifd < 8 or first_ifd >= len(data) - offset:
        return None

    return Structure(
        f"TIFF-{endian}",
        offset,
        None,
        f"magic={magic}, first_ifd={first_ifd}",
        "high",
    )


def scan_tiff_structures(data: bytes) -> list[Structure]:
    result = []
    seen = set()

    start = 0

    while True:
        p1 = data.find(
            TIFF_LE,
            start,
        )
        p2 = data.find(
            TIFF_BE,
            start,
        )

        candidates = [
            p for p in (p1, p2)
            if p >= 0
        ]

        if not candidates:
            break

        offset = min(candidates)

        obj = validate_tiff_header(
            data,
            offset,
        )

        if obj:
            key = (
                obj.kind,
                obj.offset,
            )

            if key not in seen:
                result.append(obj)
                seen.add(key)

        start = offset + 1

    return result


# ---------------------------------------------------------------------------
# Other format validators
# ---------------------------------------------------------------------------

def validate_png(data: bytes, offset: int) -> Optional[Structure]:
    if data[offset:offset + 8] != PNG_SIG:
        return None

    if offset + 24 > len(data):
        return None

    length = int.from_bytes(
        data[offset + 8:offset + 12],
        "big",
    )

    if data[offset + 12:offset + 16] != b"IHDR":
        return None

    if length != 13:
        return None

    width = int.from_bytes(
        data[offset + 16:offset + 20],
        "big",
    )
    height = int.from_bytes(
        data[offset + 20:offset + 24],
        "big",
    )

    if not (
        1 <= width <= 200000
        and
        1 <= height <= 200000
    ):
        return None

    return Structure(
        "PNG",
        offset,
        None,
        f"{width}x{height}",
        "high",
    )


def validate_pdf(data: bytes, offset: int) -> Optional[Structure]:
    if data[offset:offset + 5] != PDF:
        return None

    return Structure(
        "PDF",
        offset,
        None,
        "PDF header",
        "medium",
    )


def validate_zip(data: bytes, offset: int) -> Optional[Structure]:
    if data[offset:offset + 4] != ZIP_LOCAL:
        return None

    if offset + 30 > len(data):
        return None

    version_needed = int.from_bytes(
        data[offset + 4:offset + 6],
        "little",
    )
    name_len = int.from_bytes(
        data[offset + 26:offset + 28],
        "little",
    )
    extra_len = int.from_bytes(
        data[offset + 28:offset + 30],
        "little",
    )

    if version_needed == 0:
        return None

    end = (
        offset
        + 30
        + name_len
        + extra_len
    )

    if end > len(data):
        return None

    return Structure(
        "ZIP",
        offset,
        end,
        f"name_len={name_len}, extra_len={extra_len}",
        "medium",
    )


def validate_riff(data: bytes, offset: int) -> Optional[Structure]:
    if data[offset:offset + 4] != RIFF:
        return None

    if offset + 12 > len(data):
        return None

    size = int.from_bytes(
        data[offset + 4:offset + 8],
        "little",
    )
    form = data[offset + 8:offset + 12]

    if form not in (
        b"WAVE",
        b"AVI ",
        b"WEBP",
    ):
        return None

    end = offset + 8 + size

    if end > len(data):
        return None

    return Structure(
        f"RIFF/{form.decode('ascii').strip()}",
        offset,
        end,
        f"declared_size={size}",
        "high",
    )


def validate_iso_bmff(data: bytes, offset: int) -> Optional[Structure]:
    if offset + 12 > len(data):
        return None

    box_size = int.from_bytes(
        data[offset:offset + 4],
        "big",
    )
    box_type = data[offset + 4:offset + 8]

    if box_type != b"ftyp":
        return None

    if box_size < 16:
        return None

    end = offset + box_size

    if end > len(data):
        return None

    brand = data[
        offset + 8:offset + 12
    ].decode(
        "ascii",
        errors="replace",
    )

    return Structure(
        "ISO-BMFF",
        offset,
        end,
        f"ftyp={brand}, box_size={box_size}",
        "high",
    )


def scan_known_structures(data: bytes) -> list[Structure]:
    result = []
    seen = set()

    # Start-of-file detection.
    for obj in detect_magic(data):
        seen.add((obj.kind, obj.offset))
        result.append(obj)

    # Embedded TIFF/RAW-like metadata.
    for obj in scan_tiff_structures(data):
        key = (obj.kind, obj.offset)
        if key not in seen:
            seen.add(key)
            result.append(obj)

    validators = [
        (
            PNG_SIG,
            validate_png,
        ),
        (
            ZIP_LOCAL,
            validate_zip,
        ),
        (
            PDF,
            validate_pdf,
        ),
        (
            RIFF,
            validate_riff,
        ),
    ]

    for signature, validator in validators:
        pos = 0

        while True:
            p = data.find(
                signature,
                pos,
            )

            if p < 0:
                break

            try:
                obj = validator(
                    data,
                    p,
                )
            except Exception:
                obj = None

            if obj:
                key = (
                    obj.kind,
                    obj.offset,
                )

                if key not in seen:
                    seen.add(key)
                    result.append(obj)

            pos = p + 1

    # ISO-BMFF ftyp boxes.
    pos = 0

    while True:
        p = data.find(
            b"ftyp",
            pos,
        )

        if p < 0:
            break

        candidate_offset = p - 4

        if candidate_offset >= 0:
            obj = validate_iso_bmff(
                data,
                candidate_offset,
            )

            if obj:
                key = (
                    obj.kind,
                    obj.offset,
                )

                if key not in seen:
                    seen.add(key)
                    result.append(obj)

        pos = p + 1

    return sorted(
        result,
        key=lambda x: x.offset,
    )


def detect_magic(data: bytes) -> list[Structure]:
    result = []

    if data.startswith(PNG_SIG):
        result.append(
            Structure(
                "PNG",
                0,
                None,
                "PNG",
                "high",
            )
        )

    if data.startswith(TIFF_LE):
        result.append(
            Structure(
                "TIFF-LE",
                0,
                None,
                "TIFF",
                "high",
            )
        )

    if data.startswith(TIFF_BE):
        result.append(
            Structure(
                "TIFF-BE",
                0,
                None,
                "TIFF",
                "high",
            )
        )

    if data.startswith(PDF):
        result.append(
            Structure(
                "PDF",
                0,
                None,
                "PDF",
                "high",
            )
        )

    if data.startswith(ZIP_LOCAL):
        result.append(
            Structure(
                "ZIP",
                0,
                None,
                "ZIP",
                "high",
            )
        )

    if data.startswith(RIFF) and len(data) >= 12:
        form = data[8:12]
        name = form.decode(
            "ascii",
            errors="replace",
        )
        result.append(
            Structure(
                f"RIFF/{name}",
                0,
                None,
                "RIFF",
                "high",
            )
        )

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def make_output_dir(source: Path) -> Path:
    """
    Restore recovered files directly into the same folder as the source .hrr.

    Example:
        C:\Data\Photos\IMG_001.jpg.hrr
        -> C:\Data\Photos\IMG_001.jpg.recovered_01.jpg

    Thumbnail/preview outputs are placed into:
        C:\Data\Photos\thumbnail\
    """
    return source.parent


def save_jpeg(
    source: Path,
    blob: bytes,
    width: int,
    height: int,
    index: int,
    origin: str,
):
    target_dir = make_output_dir(source)

    kind = (
        "full"
        if width >= 800 or height >= 600
        else "thumbnail"
    )

    if kind == "thumbnail":
        target_dir = target_dir / "thumbnail"
        target_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    output = target_dir / (
        f"{safe_name(source.stem)}"
        f".recovered_{index:02d}.jpg"
    )

    counter = 1
    base = output

    while output.exists():
        output = base.with_name(
            f"{base.stem}_{counter}{base.suffix}"
        )
        counter += 1

    output.write_bytes(blob)

    log.info(
        "RECOVERED JPEG | %s | %sx%s | "
        "%d bytes | origin=%s | sha256=%s",
        output,
        width,
        height,
        len(blob),
        origin,
        sha256(blob),
    )

    return output


def save_raw_candidate(
    source: Path,
    extension: str,
    blob: bytes,
    index: int,
    origin: str,
):
    target_dir = make_output_dir(source)

    ext = extension.lower()

    if not ext.startswith("."):
        ext = ".bin"

    output = target_dir / (
        f"{safe_name(source.stem)}"
        f".recovered_{index:02d}{ext}"
    )

    counter = 1
    base = output

    while output.exists():
        output = base.with_name(
            f"{base.stem}_{counter}{base.suffix}"
        )
        counter += 1

    output.write_bytes(blob)

    log.info(
        "RECOVERED CONTAINER | %s | bytes=%d | "
        "origin=%s | sha256=%s",
        output,
        len(blob),
        origin,
        sha256(blob),
    )

    return output


# ---------------------------------------------------------------------------
# Main per-file logic
# ---------------------------------------------------------------------------

def process_file(source: Path):
    hint = parse_original_extension(
        source
    )

    data = source.read_bytes()

    log.info(
        "PROCESSING | %s",
        source,
    )
    log.info(
        "HINT | original_name=%s | extension=%s | category=%s",
        hint.original_name,
        hint.extension or "(none)",
        classify_extension_hint(
            hint.extension
        ),
    )
    log.info(
        "SOURCE | bytes=%d | sha256=%s",
        len(data),
        sha256(data),
    )

    footer = parse_harr_footer(data)

    if footer:
        log.info(
            "HARR | start=%d | end=%d | "
            "version=%d | constant=0x%08X | "
            "footer_offset=%d",
            footer["start"],
            footer["end"],
            footer["version"],
            footer["constant"],
            footer["footer_offset"],
        )

    structures = scan_known_structures(
        data
    )

    for obj in structures:
        log.info(
            "STRUCTURE | type=%s | offset=%d | "
            "end=%s | confidence=%s | %s",
            obj.kind,
            obj.offset,
            obj.end,
            obj.confidence,
            obj.details,
        )

    complete_jpegs = find_valid_jpegs(
        data
    )

    log.info(
        "JPEG | valid_objects=%d",
        len(complete_jpegs),
    )

    output_index = 1

    for obj in complete_jpegs:
        blob = data[
            obj.start:obj.end
        ]

        save_jpeg(
            source,
            blob,
            obj.width,
            obj.height,
            output_index,
            f"direct:{obj.start}-{obj.end}",
        )

        output_index += 1

    # Reconstruction for non-complete JPEG regions.
    known_ranges = [
        (obj.start, obj.end)
        for obj in complete_jpegs
    ]

    if footer:
        known_ranges.append(
            (
                footer["start"],
                footer["end"],
            )
        )

    # Merge known ranges.
    known_ranges.sort()

    merged = []
    for start, end in known_ranges:
        if not merged or start > merged[-1][1]:
            merged.append(
                [start, end]
            )
        else:
            merged[-1][1] = max(
                merged[-1][1],
                end,
            )

    boundaries = {0, len(data)}

    for start, end in merged:
        boundaries.add(start)
        boundaries.add(end)

    points = sorted(boundaries)

    candidate_regions = []

    for start, end in zip(
        points,
        points[1:],
    ):
        if not any(
            start >= x and end <= y
            for x, y in merged
        ):
            if end - start >= MIN_EMBEDDED_JPEG:
                candidate_regions.append(
                    (start, end)
                )

    for region_start, region_end in candidate_regions:
        region = data[
            region_start:region_end
        ]

        # We only attempt the special SOI reconstruction for image-like
        # extensions and for regions containing JPEG markers/MPF.
        hint_category = classify_extension_hint(
            hint.extension
        )

        region_is_image_like = (
            hint_category in {
                "jpeg",
                "raw",
                "tiff",
            }
            or
            region.find(
                b"MPF"
            ) >= 0
            or
            region.find(
                b"\xFF\xE2"
            ) >= 0
            or
            region.find(
                b"\xFF\xDA"
            ) >= 0
        )

        if not region_is_image_like:
            continue

        attempts = reconstruct_missing_soi(
            region
        )

        for label, candidate in attempts:
            valid, width, height = (
                jpeg_is_valid(
                    candidate
                )
            )

            log.info(
                "RECON TEST | region=%d-%d | "
                "method=%s | valid=%s | "
                "dimensions=%s x %s | bytes=%d",
                region_start,
                region_end,
                label,
                valid,
                width,
                height,
                len(candidate),
            )

            if not valid:
                continue

            save_jpeg(
                source,
                candidate,
                width,
                height,
                output_index,
                f"reconstructed:{region_start}-{region_end}:{label}",
            )

            output_index += 1
            break

    # RAW/TIFF/other container reconstruction is deliberately conservative:
    # save only if a validated bounded structure has an explicit end.
    # This avoids creating bogus .nef/.cr3 files from random bytes.

    for obj in structures:
        if obj.end and obj.offset < obj.end <= len(data):
            size = obj.end - obj.offset

            if size < MIN_EMBEDDED_JPEG:
                continue

            # Only save bounded container objects, and avoid simply saving
            # the full source again.
            if obj.kind in {
                "ZIP",
                "RIFF/WAVE",
                "RIFF/AVI",
                "RIFF/WEBP",
                "ISO-BMFF",
            }:
                blob = data[
                    obj.offset:obj.end
                ]

                # Use original extension when it matches the detected class;
                # otherwise use a generic container suffix.
                save_ext = hint.extension

                expected = classify_extension_hint(
                    hint.extension
                )

                if (
                    obj.kind.startswith(
                        "RIFF/"
                    )
                    and expected not in {
                        "video"
                    }
                ):
                    save_ext = ".riff"

                if (
                    obj.kind == "ISO-BMFF"
                    and expected not in {
                        "video"
                    }
                ):
                    save_ext = ".mp4"

                if obj.kind == "ZIP":
                    save_ext = (
                        hint.extension
                        if expected == "zip_based_office"
                        else ".zip"
                    )

                save_raw_candidate(
                    source,
                    save_ext or ".bin",
                    blob,
                    output_index,
                    f"validated:{obj.kind}@{obj.offset}",
                )

                output_index += 1

    # Report.
    relative = str(
        source.relative_to(ROOT)
    ).replace(
        os.sep,
        "__",
    )

    report_path = (
        REPORT_DIR
        / f"{safe_name(relative)}.txt"
    )

    with report_path.open(
        "w",
        encoding="utf-8",
    ) as report:
        report.write(
            "HRR RECONSTRUCTOR V2 REPORT\n"
        )
        report.write("=" * 100 + "\n")
        report.write(
            f"Source: {source}\n"
        )
        report.write(
            f"Original extension hint: "
            f"{hint.extension or '(none)'}\n"
        )
        report.write(
            f"Hint category: "
            f"{classify_extension_hint(hint.extension)}\n"
        )
        report.write(
            f"Size: {len(data)}\n"
        )
        report.write(
            f"SHA256: {sha256(data)}\n"
        )

        report.write(
            "\nHARR FOOTER\n"
        )
        report.write("-" * 100 + "\n")
        report.write(
            f"{footer}\n"
            if footer
            else
            "NOT FOUND\n"
        )

        report.write(
            "\nDETECTED STRUCTURES\n"
        )
        report.write("-" * 100 + "\n")
        for obj in structures:
            report.write(
                f"{obj}\n"
            )

        if not structures:
            report.write(
                "None\n"
            )

        report.write(
            "\nVALID JPEG OBJECTS\n"
        )
        report.write("-" * 100 + "\n")
        for obj in complete_jpegs:
            report.write(
                f"{obj}\n"
            )

        if not complete_jpegs:
            report.write(
                "None\n"
            )

    log.info(
        "REPORT | %s",
        report_path,
    )

    return max(
        0,
        output_index - 1,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    errors = 0
    recovered_files = 0

    log.info("=" * 100)
    log.info(
        "%s START",
        APP,
    )
    log.info(
        "ROOT=%s",
        ROOT,
    )
    log.info(
        "LOG=%s",
        LOG_FILE,
    )
    log.info(
        "REPORTS=%s",
        REPORT_DIR,
    )
    log.info(
        "OUTPUT MODE=SOURCE CURRENT PATH",
    )
    log.info(
        "PIL=%s",
        "AVAILABLE"
        if PIL_AVAILABLE
        else "NOT AVAILABLE",
    )
    log.info("=" * 100)

    try:
        files = sorted(
            iter_hrr_files(ROOT),
            key=lambda p: str(p).lower(),
        )
    except Exception:
        errors += 1
        log.exception(
            "SCAN ERROR"
        )
        files = []

    log.info(
        "SCAN COMPLETE | found=%d .hrr files",
        len(files),
    )

    for index, source in enumerate(
        files,
        1,
    ):
        log.info(
            "FILE %d/%d",
            index,
            len(files),
        )

        try:
            result = process_file(
                source
            )
            if isinstance(result, int):
                recovered_files += result
        except Exception:
            errors += 1
            log.exception(
                "FILE ERROR | %s",
                source,
            )

    log.info("=" * 100)
    log.info(
        "SUMMARY | files=%d | "
        "recovered_outputs=%d | errors=%d",
        len(files),
        recovered_files,
        errors,
    )
    log.info(
        "LOG=%s",
        LOG_FILE,
    )
    log.info(
        "REPORTS=%s",
        REPORT_DIR,
    )
    log.info(
        "OUTPUT MODE=SOURCE CURRENT PATH",
    )
    log.info("=" * 100)

    print()
    print("=" * 100)
    print("HRR Reconstructor V2 finished.")
    print(f"Recovered outputs: {recovered_files}")
    print(f"Reports: {REPORT_DIR}")
    print("Recovery: same folder as each .hrr source file")
    print(f"Log: {LOG_FILE}")
    print("Original .hrr files were not modified.")
    print("Press ENTER to close.")
    print("=" * 100)

    try:
        input()
    except EOFError:
        pass

    return errors


if __name__ == "__main__":
    raise SystemExit(main())

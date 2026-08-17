"""HARR footer parser.

The parser intentionally exposes unknown fields as raw bytes. No semantic
meaning is assigned to the 24-byte per-file field until evidence supports it.
"""

from __future__ import annotations

from dataclasses import dataclass


HARR_MAGIC = b"HARR"
HARR_FOOTER_SIZE = 49
HARR_VERSION = 21
HARR_CONSTANT = 0x00001000


class HARRFooterError(ValueError):
    """Raised when a candidate HARR footer fails structural validation."""


@dataclass(frozen=True)
class HARRFooter:
    """Validated 49-byte HARR footer."""

    start: int
    end: int
    version: int
    field24: bytes
    footer_offset: int
    constant: int
    reserved: bytes

    @property
    def size(self) -> int:
        return self.end - self.start


def parse_harr_footer(
    data: bytes,
    *,
    expected_version: int | None = HARR_VERSION,
    expected_constant: int | None = HARR_CONSTANT,
    search_from_end: bool = True,
) -> HARRFooter:
    """Find and validate a HARR footer.

    The footer layout currently established by the investigation is:

        0..3    HARR
        4       version
        5..28   24-byte per-file field
        29..32  reserved
        33..36  footer offset (big-endian uint32)
        37..40  constant (big-endian uint32)
        41..44  reserved
        45..48  HARR

    Unknown/reserved bytes are preserved verbatim. The stored footer offset
    must point exactly to the beginning of the validated footer.
    """
    if len(data) < HARR_FOOTER_SIZE:
        raise HARRFooterError(
            f"data too short for HARR footer: {len(data)} < {HARR_FOOTER_SIZE}"
        )

    starts: list[int] = []
    first = len(data) - HARR_FOOTER_SIZE if search_from_end else 0
    last = -1 if search_from_end else len(data) - HARR_FOOTER_SIZE + 1
    step = -1 if search_from_end else 1

    for offset in range(first, last, step):
        if data[offset : offset + 4] == HARR_MAGIC:
            starts.append(offset)

    if not starts:
        raise HARRFooterError("HARR footer magic not found")

    failures: list[str] = []
    for start in starts:
        footer = data[start : start + HARR_FOOTER_SIZE]
        if len(footer) != HARR_FOOTER_SIZE:
            failures.append(f"offset {start}: truncated footer")
            continue
        if footer[-4:] != HARR_MAGIC:
            failures.append(f"offset {start}: trailing HARR marker missing")
            continue

        version = footer[4]
        field24 = footer[5:29]
        reserved_a = footer[29:33]
        footer_offset = int.from_bytes(footer[33:37], "big")
        constant = int.from_bytes(footer[37:41], "big")
        reserved_b = footer[41:45]

        if footer_offset != start:
            failures.append(
                f"offset {start}: footer_offset={footer_offset} does not match start"
            )
            continue
        if expected_version is not None and version != expected_version:
            failures.append(
                f"offset {start}: unsupported version {version} "
                f"(expected {expected_version})"
            )
            continue
        if expected_constant is not None and constant != expected_constant:
            failures.append(
                f"offset {start}: unexpected constant 0x{constant:08X} "
                f"(expected 0x{expected_constant:08X})"
            )
            continue

        return HARRFooter(
            start=start,
            end=start + HARR_FOOTER_SIZE,
            version=version,
            field24=field24,
            footer_offset=footer_offset,
            constant=constant,
            reserved=reserved_a + reserved_b,
        )

    raise HARRFooterError("no structurally valid HARR footer found: " + "; ".join(failures))

"""Research-only notes and compatibility helpers.

This module intentionally contains no cryptographic operations.
"""

from .footer import HARRFooter


def footer_summary(footer: HARRFooter) -> dict[str, int | str]:
    """Return a stable, JSON-friendly summary for forensic reports."""
    return {
        "start": footer.start,
        "end": footer.end,
        "size": footer.size,
        "version": footer.version,
        "footer_offset": footer.footer_offset,
        "constant": f"0x{footer.constant:08X}",
    }

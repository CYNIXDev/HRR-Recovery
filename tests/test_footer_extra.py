from hrr.footer import parse_harr_footer


def test_parser_uses_last_valid_footer_candidate():
    prefix = b"x" * 10
    footer = (
        b"HARR" + bytes([21]) + bytes(24) + b"\x00" * 4
        + len(prefix).to_bytes(4, "big")
        + (0x1000).to_bytes(4, "big") + b"\x00" * 4 + b"HARR"
    )
    result = parse_harr_footer(prefix + footer)
    assert result.start == 10

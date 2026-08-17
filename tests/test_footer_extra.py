from hrr.footer import parse_harr_footer


def make_footer(start: int) -> bytes:
    return (
        b"HARR"
        + bytes([21])
        + bytes(24)
        + b"\x00" * 4
        + start.to_bytes(4, "big")
        + (0x1000).to_bytes(4, "big")
        + b"\x00" * 4
        + b"HARR"
    )


def test_parser_uses_last_valid_footer_candidate():
    first_prefix = b"x" * 10
    first_footer = make_footer(len(first_prefix))
    second_prefix = first_prefix + first_footer + b"payload"
    second_footer = make_footer(len(second_prefix))

    result = parse_harr_footer(second_prefix + second_footer)

    assert result.start == len(second_prefix)
    assert result.end == len(second_prefix) + 49

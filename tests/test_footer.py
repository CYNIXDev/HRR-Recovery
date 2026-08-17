from hrr.footer import HARR_FOOTER_SIZE, HARRFooterError, parse_harr_footer


def make_footer(start: int, *, version: int = 21, constant: int = 0x1000) -> bytes:
    return (
        b"HARR"
        + bytes([version])
        + bytes(range(24))
        + b"\x00\x00\x00\x00"
        + start.to_bytes(4, "big")
        + constant.to_bytes(4, "big")
        + b"\x00\x00\x00\x00"
        + b"HARR"
    )


def test_valid_footer_at_end():
    prefix = b"media-data"
    footer = make_footer(len(prefix))
    result = parse_harr_footer(prefix + footer)

    assert result.start == len(prefix)
    assert result.end == len(prefix) + HARR_FOOTER_SIZE
    assert result.version == 21
    assert result.field24 == bytes(range(24))
    assert result.footer_offset == len(prefix)
    assert result.constant == 0x1000
    assert result.reserved == b"\x00" * 8


def test_footer_offset_must_match_position():
    prefix = b"media-data"
    footer = bytearray(make_footer(len(prefix)))
    footer[33:37] = (0).to_bytes(4, "big")

    try:
        parse_harr_footer(prefix + footer)
    except HARRFooterError as exc:
        assert "footer_offset" in str(exc)
    else:
        raise AssertionError("invalid footer was accepted")


def test_truncated_footer_rejected():
    try:
        parse_harr_footer(b"HARR" + b"\x00" * 20)
    except HARRFooterError as exc:
        assert "too short" in str(exc)
    else:
        raise AssertionError("truncated footer was accepted")


def test_wrong_version_rejected():
    prefix = b"x" * 32
    footer = make_footer(len(prefix), version=22)

    try:
        parse_harr_footer(prefix + footer)
    except HARRFooterError as exc:
        assert "unsupported version" in str(exc)
    else:
        raise AssertionError("wrong version was accepted")


def test_wrong_constant_rejected():
    prefix = b"x" * 32
    footer = make_footer(len(prefix), constant=0x2000)

    try:
        parse_harr_footer(prefix + footer)
    except HARRFooterError as exc:
        assert "unexpected constant" in str(exc)
    else:
        raise AssertionError("wrong constant was accepted")


def test_missing_trailing_magic_rejected():
    prefix = b"x" * 32
    footer = bytearray(make_footer(len(prefix)))
    footer[-4:] = b"NOPE"

    try:
        parse_harr_footer(prefix + footer)
    except HARRFooterError as exc:
        assert "trailing HARR" in str(exc)
    else:
        raise AssertionError("invalid trailing marker was accepted")

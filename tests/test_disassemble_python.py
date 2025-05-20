from research.disassemble_python import (
    is_hex,
    is_base64,
    is_valid_ip,
    is_valid_url,
    is_escaped_hex,
)


def test_is_url():
    assert is_valid_url("https://example.com")
    assert is_valid_url("http://example.com/path")
    assert not is_valid_url("not a url")


def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1")
    assert is_valid_ip("8.8.8.8")
    assert not is_valid_ip("999.999.999.999")
    assert is_valid_ip("2001:db8::1")
    assert not is_valid_ip("not.an.ip")


def test_is_hex():
    assert not is_hex("dGVzdA==")
    assert is_hex("48656c6c6f")


def test_is_base64():
    assert is_base64("dGVzdA==")
    assert not is_base64("####")


def test_is_escaped_hex():
    assert is_escaped_hex(r"\xbf\x82\xe6\x05")
    assert not is_escaped_hex("abc")

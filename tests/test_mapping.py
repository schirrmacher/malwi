from research.mapping import (
    map_entropy_to_token,
    map_string_length_to_token,
    calculate_shannon_entropy,
    is_valid_ip,
    is_valid_url,
    is_escaped_hex,
    is_base64,
    is_file_path,
)


def test_map_entropy_to_token():
    assert map_entropy_to_token(0.5) == "ENT_LOW"


def test_map_string_length_to_token():
    assert map_string_length_to_token(5) == "LEN_XS"


def test_calculate_shannon_entropy():
    assert calculate_shannon_entropy(b"aabb") == 1.0


def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1")


def test_is_valid_url():
    assert is_valid_url("http://example.com")


def test_is_escaped_hex():
    assert is_escaped_hex(r"\x41\x42\x43")


def test_is_base64():
    assert is_base64("SGVsbG8gd29ybGQ=")
    assert not is_base64("SGVsbG8gd29ybGQ")


def test_is_file_path():
    assert is_file_path("/usr/bin/python")
    assert is_file_path(r"\x68\x65\x6c\x6c\x6f")

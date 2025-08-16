from common.mapping import (
    is_valid_ip,
    is_valid_url,
    is_escaped_hex,
    is_base64,
    is_file_path,
    is_localhost,
    contains_url,
    map_entropy_to_token,
    map_string_length_to_token,
    calculate_shannon_entropy,
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
    # Escaped hex strings should not be considered file paths
    assert not is_file_path(r"\x68\x65\x6c\x6c\x6f")
    # But actual file paths should be
    assert is_file_path("./config.json")
    assert is_file_path("C:\\Windows\\System32\\cmd.exe")
    assert is_file_path("script.py")


def test_is_localhost():
    # Test exact localhost patterns
    assert is_localhost("localhost")
    assert is_localhost("127.0.0.1")
    assert is_localhost("::1")
    assert is_localhost("0.0.0.0")
    assert is_localhost("local")
    assert is_localhost("loopback")

    # Test localhost with ports
    assert is_localhost("localhost:8080")
    assert is_localhost("127.0.0.1:3000")

    # Test localhost in URLs
    assert is_localhost("http://localhost/api")
    assert is_localhost("https://127.0.0.1:8080/test")

    # Test private network ranges (RFC 1918)
    assert is_localhost("192.168.1.1")
    assert is_localhost("10.0.0.1")
    assert is_localhost("172.16.0.1")
    assert is_localhost("172.31.255.255")

    # Test non-localhost addresses
    assert not is_localhost("google.com")
    assert not is_localhost("8.8.8.8")
    assert not is_localhost("172.32.0.1")  # Outside private range
    assert not is_localhost("192.169.1.1")  # Outside private range
    assert not is_localhost("")
    assert not is_localhost("just_text")


def test_contains_url():
    # Test strings that contain URLs
    assert contains_url("Check out https://example.com for more info")
    assert contains_url("Visit http://test.com or ftp://files.com")
    assert contains_url("JavaScript: javascript:alert('test')")
    assert contains_url("Data URI: data:text/plain;base64,SGVsbG8=")
    assert contains_url("SSH to ssh://user@server.com")
    assert contains_url("Use telnet://host:23 for connection")
    assert contains_url("File at file:///path/to/file")
    assert contains_url("Script with vbscript:msgbox('hello')")

    # Test strings that don't contain URLs
    assert not contains_url("This is just plain text")
    assert not contains_url("No protocols here")
    assert not contains_url("http")  # Too short
    assert not contains_url("://example")  # No protocol
    assert not contains_url("")
    assert not contains_url("short")  # Below minimum length

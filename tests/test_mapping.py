import dis
import pytest

from unittest.mock import MagicMock

from research.mapping import (
    SpecialCases,
    is_valid_ip,
    is_valid_url,
    is_escaped_hex,
    is_base64,
    is_file_path,
    is_localhost,
    contains_url,
    # Service category URL detection functions
    is_version_control_url,
    is_code_snippets_url,
    is_package_manager_url,
    is_cloud_hosting_url,
    is_documentation_url,
    is_messenger_url,
    is_ci_cd_url,
    is_monitoring_url,
    is_database_url,
    map_entropy_to_token,
    map_string_length_to_token,
    map_code_object_arg,
    map_frozenset_arg,
    calculate_shannon_entropy,
    map_load_const_number_arg,
    map_jump_instruction_arg,
    map_tuple_arg,
    map_string_arg,
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
    assert is_valid_url("https://example.com")
    assert is_valid_url("ftp://files.example.com")
    assert not is_valid_url("not-a-url")
    assert not is_valid_url("just a string")


def test_is_https_url():
    from research.mapping import is_https_url

    # Valid HTTPS URLs
    assert is_https_url("https://example.com")
    assert is_https_url("https://subdomain.example.org/path")
    assert is_https_url("https://192.168.1.1")
    assert is_https_url("https://10.0.0.1:443/secure")

    # Not HTTPS URLs
    assert not is_https_url("http://example.com")
    assert not is_https_url("ftp://example.com")
    assert not is_https_url("not-a-url")
    assert not is_https_url("")


def test_is_http_url():
    from research.mapping import is_http_url

    # Valid HTTP URLs
    assert is_http_url("http://example.com")
    assert is_http_url("http://subdomain.example.org/path")
    assert is_http_url("http://8.149.140.24:8082")
    assert is_http_url("http://192.168.1.1/api")

    # Not HTTP URLs
    assert not is_http_url("https://example.com")
    assert not is_http_url("ftp://example.com")
    assert not is_http_url("not-a-url")
    assert not is_http_url("")


def test_is_https_url_with_ip():
    from research.mapping import is_https_url_with_ip

    # HTTPS URLs with IP addresses
    assert is_https_url_with_ip("https://192.168.1.1")
    assert is_https_url_with_ip("https://10.0.0.1:443/secure")
    assert is_https_url_with_ip("https://172.16.0.1/admin")
    assert is_https_url_with_ip("https://8.8.8.8")

    # HTTPS URLs with domains (not IPs)
    assert not is_https_url_with_ip("https://example.com")
    assert not is_https_url_with_ip("https://google.com:443")

    # HTTP URLs with IPs (wrong protocol)
    assert not is_https_url_with_ip("http://192.168.1.1")

    # Not URLs
    assert not is_https_url_with_ip("192.168.1.1")
    assert not is_https_url_with_ip("")


def test_is_http_url_with_ip():
    from research.mapping import is_http_url_with_ip

    # HTTP URLs with IP addresses
    assert is_http_url_with_ip("http://192.168.1.1")
    assert is_http_url_with_ip("http://8.149.140.24:8082")
    assert is_http_url_with_ip("http://10.0.0.1/api")
    assert is_http_url_with_ip("http://172.31.255.255:8080/malware")

    # HTTP URLs with domains (not IPs)
    assert not is_http_url_with_ip("http://example.com")
    assert not is_http_url_with_ip("http://malicious-site.org")

    # HTTPS URLs with IPs (wrong protocol)
    assert not is_http_url_with_ip("https://192.168.1.1")

    # Not URLs
    assert not is_http_url_with_ip("192.168.1.1")
    assert not is_http_url_with_ip("")


def test_url_detection_edge_cases():
    """Test edge cases for URL detection functions."""
    from research.mapping import (
        is_https_url,
        is_http_url,
        is_https_url_with_ip,
        is_http_url_with_ip,
    )

    # IPv6 addresses
    assert is_http_url_with_ip("http://[::1]:8080")  # IPv6 localhost
    assert is_https_url_with_ip("https://[2001:db8::1]")  # IPv6 address

    # URLs with authentication
    assert is_http_url_with_ip("http://user:pass@192.168.1.1/path")
    assert is_https_url_with_ip("https://admin:secret@10.0.0.1:443")

    # URLs with query strings and fragments
    assert is_http_url("http://evil.com/path?cmd=exec&file=/etc/passwd")
    assert is_https_url("https://site.org/page#section")

    # Invalid IP addresses should not match IP URL patterns
    assert not is_http_url_with_ip("http://999.999.999.999")  # Invalid IP
    assert not is_https_url_with_ip("https://256.256.256.256")  # Invalid IP

    # Mixed case schemes
    assert is_http_url("HTTP://EXAMPLE.COM")
    assert is_https_url("HTTPS://EXAMPLE.COM")

    # Empty and None cases
    assert not is_http_url("")
    assert not is_https_url("")
    assert not is_http_url_with_ip("")
    assert not is_https_url_with_ip("")


def test_url_mapping_priority():
    """Test that URL mapping follows the correct priority order."""
    from research.mapping import map_string_arg, SpecialCases

    # Localhost should take precedence over HTTP URL with IP
    assert (
        map_string_arg("http://127.0.0.1:8080", "")
        == SpecialCases.STRING_LOCALHOST.value
    )
    assert (
        map_string_arg("http://localhost/api", "")
        == SpecialCases.STRING_LOCALHOST.value
    )

    # HTTP URL with IP should be detected correctly when not localhost
    assert (
        map_string_arg("http://8.8.8.8:80", "")
        == SpecialCases.STRING_HTTP_URL_WITH_IP.value
    )
    assert (
        map_string_arg("http://1.2.3.4/malware", "")
        == SpecialCases.STRING_HTTP_URL_WITH_IP.value
    )

    # HTTPS URL with IP should be detected correctly
    assert (
        map_string_arg("https://8.8.8.8:443", "")
        == SpecialCases.STRING_HTTPS_URL_WITH_IP.value
    )

    # Regular HTTP/HTTPS URLs
    assert map_string_arg("http://evil.com", "") == SpecialCases.STRING_HTTP_URL.value
    assert (
        map_string_arg("https://secure.org", "") == SpecialCases.STRING_HTTPS_URL.value
    )

    # Other protocols should fall back to STRING_URL
    assert (
        map_string_arg("ftp://files.example.com", "") == SpecialCases.STRING_URL.value
    )
    assert map_string_arg("ssh://server.com:22", "") == SpecialCases.STRING_URL.value


def test_is_version_control_url():
    """Test version control platform URL detection."""
    # Valid version control URLs
    assert is_version_control_url("https://github.com")
    assert is_version_control_url("https://www.github.com/user/repo")
    assert is_version_control_url("https://gitlab.com/project")
    assert is_version_control_url("https://www.gitlab.com")
    assert is_version_control_url("https://bitbucket.org/team/repo")
    assert is_version_control_url("https://www.bitbucket.org")

    # Not version control URLs
    assert not is_version_control_url("https://example.com")
    assert not is_version_control_url("https://google.com")
    assert not is_version_control_url("not-a-url")
    assert not is_version_control_url("")


def test_is_code_snippets_url():
    """Test code snippet platform URL detection."""
    # Valid code snippet URLs
    assert is_code_snippets_url("https://gist.github.com/user/123456")
    assert is_code_snippets_url("https://pastebin.com/abcd1234")
    assert is_code_snippets_url("https://www.pastebin.com")
    assert is_code_snippets_url("https://codepen.io/user/pen/xyz")
    assert is_code_snippets_url("https://www.codepen.io")
    assert is_code_snippets_url("https://jsfiddle.net/user/abc123")
    assert is_code_snippets_url("https://www.jsfiddle.net")
    assert is_code_snippets_url("https://codesandbox.io/s/project")
    assert is_code_snippets_url("https://www.codesandbox.io")

    # Not code snippet URLs
    assert not is_code_snippets_url("https://github.com")
    assert not is_code_snippets_url("https://stackoverflow.com")
    assert not is_code_snippets_url("not-a-url")
    assert not is_code_snippets_url("")


def test_is_package_manager_url():
    """Test package manager platform URL detection."""
    # Valid package manager URLs
    assert is_package_manager_url("https://npmjs.com/package/react")
    assert is_package_manager_url("https://www.npmjs.com")
    assert is_package_manager_url("https://pypi.org/project/requests")
    assert is_package_manager_url("https://www.pypi.org")
    assert is_package_manager_url("https://mvnrepository.com/artifact/junit")
    assert is_package_manager_url("https://www.mvnrepository.com")
    assert is_package_manager_url("https://hub.docker.com/r/nginx")
    assert is_package_manager_url("https://www.hub.docker.com")
    assert is_package_manager_url("https://rubygems.org/gems/rails")
    assert is_package_manager_url("https://www.rubygems.org")
    assert is_package_manager_url("https://crates.io/crates/serde")
    assert is_package_manager_url("https://www.crates.io")
    assert is_package_manager_url("https://packagist.org/packages/symfony")
    assert is_package_manager_url("https://www.packagist.org")
    assert is_package_manager_url("https://nuget.org/packages/Newtonsoft.Json")
    assert is_package_manager_url("https://www.nuget.org")

    # Not package manager URLs
    assert not is_package_manager_url("https://github.com")
    assert not is_package_manager_url("https://stackoverflow.com")
    assert not is_package_manager_url("not-a-url")
    assert not is_package_manager_url("")


def test_is_cloud_hosting_url():
    """Test cloud hosting platform URL detection."""
    # Valid cloud hosting URLs
    assert is_cloud_hosting_url("https://aws.amazon.com/ec2")
    assert is_cloud_hosting_url("https://console.aws.amazon.com")
    assert is_cloud_hosting_url("https://azure.microsoft.com/services")
    assert is_cloud_hosting_url("https://portal.azure.com")
    assert is_cloud_hosting_url("https://cloud.google.com/compute")
    assert is_cloud_hosting_url("https://console.cloud.google.com")
    assert is_cloud_hosting_url("https://digitalocean.com/droplets")
    assert is_cloud_hosting_url("https://www.digitalocean.com")
    assert is_cloud_hosting_url("https://heroku.com/apps")
    assert is_cloud_hosting_url("https://www.heroku.com")
    assert is_cloud_hosting_url("https://dashboard.heroku.com")
    assert is_cloud_hosting_url("https://vercel.com/dashboard")
    assert is_cloud_hosting_url("https://www.vercel.com")
    assert is_cloud_hosting_url("https://netlify.com/sites")
    assert is_cloud_hosting_url("https://www.netlify.com")
    assert is_cloud_hosting_url("https://app.netlify.com")
    assert is_cloud_hosting_url("https://firebase.google.com/console")
    assert is_cloud_hosting_url("https://console.firebase.google.com")
    assert is_cloud_hosting_url("https://fly.io/apps")
    assert is_cloud_hosting_url("https://www.fly.io")

    # Not cloud hosting URLs
    assert not is_cloud_hosting_url("https://github.com")
    assert not is_cloud_hosting_url("https://stackoverflow.com")
    assert not is_cloud_hosting_url("not-a-url")
    assert not is_cloud_hosting_url("")


def test_is_documentation_url():
    """Test documentation/learning platform URL detection."""
    # Valid documentation URLs
    assert is_documentation_url("https://stackoverflow.com/questions/123")
    assert is_documentation_url("https://www.stackoverflow.com")
    assert is_documentation_url("https://developer.mozilla.org/docs")
    assert is_documentation_url("https://dev.to/article")
    assert is_documentation_url("https://www.dev.to")
    assert is_documentation_url("https://medium.com/@user/article")
    assert is_documentation_url("https://www.medium.com")
    assert is_documentation_url("https://freecodecamp.org/learn")
    assert is_documentation_url("https://www.freecodecamp.org")
    assert is_documentation_url("https://w3schools.com/html")
    assert is_documentation_url("https://www.w3schools.com")
    assert is_documentation_url("https://docs.microsoft.com/en-us")
    assert is_documentation_url("https://geeksforgeeks.org/article")
    assert is_documentation_url("https://www.geeksforgeeks.org")
    assert is_documentation_url("https://css-tricks.com/guide")
    assert is_documentation_url("https://www.css-tricks.com")

    # Not documentation URLs
    assert not is_documentation_url("https://github.com")
    assert not is_documentation_url("https://npmjs.com")
    assert not is_documentation_url("not-a-url")
    assert not is_documentation_url("")


def test_is_messenger_url():
    """Test messaging platform URL detection."""
    # Valid messenger URLs
    assert is_messenger_url("https://slack.com/workspace")
    assert is_messenger_url("https://www.slack.com")
    assert is_messenger_url("https://app.slack.com/client")
    assert is_messenger_url("https://discord.com/channels/123")
    assert is_messenger_url("https://www.discord.com")
    assert is_messenger_url("https://teams.microsoft.com/l/team")
    assert is_messenger_url("https://telegram.org/apps")
    assert is_messenger_url("https://www.telegram.org")
    assert is_messenger_url("https://web.telegram.org")
    assert is_messenger_url("https://whatsapp.com/download")
    assert is_messenger_url("https://www.whatsapp.com")
    assert is_messenger_url("https://web.whatsapp.com")

    # Not messenger URLs
    assert not is_messenger_url("https://github.com")
    assert not is_messenger_url("https://stackoverflow.com")
    assert not is_messenger_url("not-a-url")
    assert not is_messenger_url("")


def test_is_ci_cd_url():
    """Test CI/CD platform URL detection."""
    # Valid CI/CD URLs
    assert is_ci_cd_url("https://jenkins.io/doc")
    assert is_ci_cd_url("https://www.jenkins.io")
    assert is_ci_cd_url("https://circleci.com/docs")
    assert is_ci_cd_url("https://www.circleci.com")
    assert is_ci_cd_url("https://app.circleci.com/projects")
    assert is_ci_cd_url("https://travis-ci.org/user/repo")
    assert is_ci_cd_url("https://www.travis-ci.org")
    assert is_ci_cd_url("https://travis-ci.com/builds")
    assert is_ci_cd_url("https://www.travis-ci.com")

    # GitHub Actions specific paths
    assert is_ci_cd_url("https://github.com/features/actions")
    assert is_ci_cd_url("https://github.com/user/repo/actions")
    assert is_ci_cd_url("https://www.github.com/features/actions")

    # GitLab CI specific paths
    assert is_ci_cd_url("https://gitlab.com/user/project/-/ci/pipelines")
    assert is_ci_cd_url("https://about.gitlab.com/stages-devops-lifecycle/verify/")
    assert is_ci_cd_url("https://www.gitlab.com/features/ci-cd")

    # Not CI/CD URLs (regular GitHub/GitLab without CI paths)
    assert not is_ci_cd_url("https://github.com/user/repo")
    assert not is_ci_cd_url("https://gitlab.com/user/project")
    assert not is_ci_cd_url("https://stackoverflow.com")
    assert not is_ci_cd_url("not-a-url")
    assert not is_ci_cd_url("")


def test_is_monitoring_url():
    """Test monitoring/observability platform URL detection."""
    # Valid monitoring URLs
    assert is_monitoring_url("https://datadoghq.com/dashboards")
    assert is_monitoring_url("https://www.datadoghq.com")
    assert is_monitoring_url("https://app.datadoghq.com")
    assert is_monitoring_url("https://newrelic.com/platform")
    assert is_monitoring_url("https://www.newrelic.com")
    assert is_monitoring_url("https://one.newrelic.com")
    assert is_monitoring_url("https://sentry.io/organizations")
    assert is_monitoring_url("https://www.sentry.io")
    assert is_monitoring_url("https://grafana.com/grafana")
    assert is_monitoring_url("https://www.grafana.com")
    assert is_monitoring_url("https://prometheus.io/docs")
    assert is_monitoring_url("https://www.prometheus.io")

    # Not monitoring URLs
    assert not is_monitoring_url("https://github.com")
    assert not is_monitoring_url("https://stackoverflow.com")
    assert not is_monitoring_url("not-a-url")
    assert not is_monitoring_url("")


def test_is_database_url():
    """Test database platform URL detection."""
    # Valid database URLs
    assert is_database_url("https://mongodb.com/atlas")
    assert is_database_url("https://www.mongodb.com")
    assert is_database_url("https://cloud.mongodb.com")
    assert is_database_url("https://postgresql.org/docs")
    assert is_database_url("https://www.postgresql.org")
    assert is_database_url("https://redis.io/commands")
    assert is_database_url("https://www.redis.io")
    assert is_database_url("https://mysql.com/products")
    assert is_database_url("https://www.mysql.com")
    assert is_database_url("https://planetscale.com/docs")
    assert is_database_url("https://www.planetscale.com")
    assert is_database_url("https://supabase.com/dashboard")
    assert is_database_url("https://www.supabase.com")
    assert is_database_url("https://app.supabase.com")
    assert is_database_url("https://elastic.co/elasticsearch")
    assert is_database_url("https://www.elastic.co")
    assert is_database_url("https://cloud.elastic.co")

    # Not database URLs
    assert not is_database_url("https://github.com")
    assert not is_database_url("https://stackoverflow.com")
    assert not is_database_url("not-a-url")
    assert not is_database_url("")


def test_service_url_mapping_integration():
    """Test that service URLs are correctly mapped by map_string_arg."""
    from research.mapping import map_string_arg, SpecialCases

    # Version control URLs
    assert (
        map_string_arg("https://github.com/user/repo", "")
        == SpecialCases.STRING_URL_VERSION_CONTROL.value
    )
    assert (
        map_string_arg("https://gitlab.com/project", "")
        == SpecialCases.STRING_URL_VERSION_CONTROL.value
    )

    # Code snippet URLs
    assert (
        map_string_arg("https://pastebin.com/abc123", "")
        == SpecialCases.STRING_URL_CODE_SNIPPETS.value
    )
    assert (
        map_string_arg("https://gist.github.com/user/123", "")
        == SpecialCases.STRING_URL_CODE_SNIPPETS.value
    )

    # Package manager URLs
    assert (
        map_string_arg("https://pypi.org/project/requests", "")
        == SpecialCases.STRING_URL_PACKAGE_MANAGER.value
    )
    assert (
        map_string_arg("https://npmjs.com/package/react", "")
        == SpecialCases.STRING_URL_PACKAGE_MANAGER.value
    )

    # Cloud hosting URLs
    assert (
        map_string_arg("https://aws.amazon.com/ec2", "")
        == SpecialCases.STRING_URL_CLOUD_HOSTING.value
    )
    assert (
        map_string_arg("https://vercel.com/dashboard", "")
        == SpecialCases.STRING_URL_CLOUD_HOSTING.value
    )

    # Documentation URLs
    assert (
        map_string_arg("https://stackoverflow.com/questions", "")
        == SpecialCases.STRING_URL_DOCUMENTATION.value
    )
    assert (
        map_string_arg("https://developer.mozilla.org/docs", "")
        == SpecialCases.STRING_URL_DOCUMENTATION.value
    )

    # Messenger URLs
    assert (
        map_string_arg("https://slack.com/workspace", "")
        == SpecialCases.STRING_URL_MESSENGER.value
    )
    assert (
        map_string_arg("https://discord.com/channels", "")
        == SpecialCases.STRING_URL_MESSENGER.value
    )

    # CI/CD URLs
    assert (
        map_string_arg("https://github.com/features/actions", "")
        == SpecialCases.STRING_URL_CI_CD.value
    )
    assert (
        map_string_arg("https://circleci.com/docs", "")
        == SpecialCases.STRING_URL_CI_CD.value
    )

    # Monitoring URLs
    assert (
        map_string_arg("https://datadoghq.com/dashboards", "")
        == SpecialCases.STRING_URL_MONITORING.value
    )
    assert (
        map_string_arg("https://sentry.io/organizations", "")
        == SpecialCases.STRING_URL_MONITORING.value
    )

    # Database URLs
    assert (
        map_string_arg("https://mongodb.com/atlas", "")
        == SpecialCases.STRING_URL_DATABASE.value
    )
    assert (
        map_string_arg("https://supabase.com/dashboard", "")
        == SpecialCases.STRING_URL_DATABASE.value
    )


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


class TestArgumentMapping:
    @pytest.mark.parametrize(
        "argval, expected_output_pattern",
        [
            ("eval", "DYNAMIC_CODE_EXECUTION"),
            ("os", "SYSTEM_INTERACTION"),
            ("/etc/passwd", SpecialCases.STRING_SENSITIVE_FILE_PATH.value),
            ("8.8.8.8", SpecialCases.STRING_IP.value),  # Public IP
            ("localhost", SpecialCases.STRING_LOCALHOST.value),  # Localhost
            ("127.0.0.1", SpecialCases.STRING_LOCALHOST.value),  # Localhost IP
            ("192.168.1.1", SpecialCases.STRING_LOCALHOST.value),  # Private IP
            # New enhanced URL types
            ("http://8.149.140.24:8082", SpecialCases.STRING_HTTP_URL_WITH_IP.value),
            ("https://192.168.1.1:443", SpecialCases.STRING_HTTPS_URL_WITH_IP.value),
            # Service category URLs
            (
                "https://github.com/user/repo",
                SpecialCases.STRING_URL_VERSION_CONTROL.value,
            ),
            (
                "https://pastebin.com/abc123",
                SpecialCases.STRING_URL_CODE_SNIPPETS.value,
            ),
            (
                "https://pypi.org/project/requests",
                SpecialCases.STRING_URL_PACKAGE_MANAGER.value,
            ),
            ("https://aws.amazon.com/ec2", SpecialCases.STRING_URL_CLOUD_HOSTING.value),
            (
                "https://stackoverflow.com/questions",
                SpecialCases.STRING_URL_DOCUMENTATION.value,
            ),
            ("https://slack.com/workspace", SpecialCases.STRING_URL_MESSENGER.value),
            (
                "https://github.com/features/actions",
                SpecialCases.STRING_URL_CI_CD.value,
            ),
            (
                "https://datadoghq.com/dashboards",
                SpecialCases.STRING_URL_MONITORING.value,
            ),
            ("https://mongodb.com/atlas", SpecialCases.STRING_URL_DATABASE.value),
            ("http://malicious-site.com", SpecialCases.STRING_HTTP_URL.value),
            ("https://secure-site.org", SpecialCases.STRING_HTTPS_URL.value),
            ("ftp://files.example.com", SpecialCases.STRING_URL.value),
            (
                "Check out https://example.com for more",
                SpecialCases.STRING_CONTAINS_URL.value,
            ),  # Contains URL
            (
                "surveymonkey.com",
                "STRING_LEN_S_ENT_HIGH",
            ),  # From MOCK_FUNCTION_MAPPING_DATA
            ("./path/to/file.txt", SpecialCases.STRING_FILE_PATH.value),
            ("short", "short"),  # len=5 <= STRING_MAX_LENGTH (15)
            # Escaped hex strings are now classified as STRING_ESCAPED_HEX
            (
                "\\x68\\x65\\x6c\\x6c\\x6f",
                f"{SpecialCases.STRING_ESCAPED_HEX.value}_LEN_S_ENT_MED",
            ),
            ("68656c6c6f", "68656c6c6f"),  # len=10 <= STRING_MAX_LENGTH (15)
            (
                "SGVsbG8gd29ybGQ=",
                f"{SpecialCases.STRING_BASE64.value}_LEN_S_ENT_HIGH",
            ),  # len=16
            ("a" * 50, f"{SpecialCases.STRING_HEX.value}_LEN_S_ENT_LOW"),  # len=50
            (
                "this_is_a_long_generic_string_greater_than_15_chars",
                "STRING_LEN_L_ENT_HIGH",
            ),  # len=55
        ],
    )
    def test_map_string_arg(self, argval, expected_output_pattern, monkeypatch):
        result = map_string_arg(argval, repr(argval))

        is_complex_token = (
            any(
                token_prefix in expected_output_pattern
                for token_prefix in [
                    SpecialCases.STRING_BASE64.value,
                    SpecialCases.STRING_HEX.value,
                    "STRING_",
                ]
            )
            and "_" in expected_output_pattern
        )

        if is_complex_token:
            parts = expected_output_pattern.split("_")
            expected_main_type_prefix = parts[0]
            # LEN_S, ENT_LOW etc. parts
            expected_suffix_parts = parts[1:]

            assert result.startswith(expected_main_type_prefix)
            for suffix_part_component in expected_suffix_parts:
                # Handle cases like "LEN_S" vs "S" or "ENT_LOW" vs "LOW"
                assert suffix_part_component in result
        else:  # For exact matches
            assert result == expected_output_pattern

    def test_map_code_object_arg(self):
        co = compile("x=1", "<string>", "exec")
        assert map_code_object_arg(co, repr(co)) == "OBJECT"

    @pytest.mark.parametrize(
        "argval, expected",
        [
            (("cmd", "/bin/sh", 123), "/bin/sh INTEGER cmd"),
            ((1.0, 2.0), SpecialCases.FLOAT.value),
            ((1.0, "text"), "FLOAT text"),
            ((), ""),
        ],
    )
    def test_map_tuple_arg(self, argval, expected):
        assert map_tuple_arg(argval, repr(argval)) == expected

    @pytest.mark.parametrize(
        "argval, expected",
        [(frozenset({"admin", "user", 404.0}), "FLOAT admin user"), (frozenset(), "")],
    )
    def test_map_frozenset_arg(self, argval, expected):
        assert map_frozenset_arg(argval, repr(argval)) == expected

    def test_map_jump_instruction_arg(self):
        mock_instr = MagicMock(spec=dis.Instruction)
        assert map_jump_instruction_arg(mock_instr) == "TO_NUMBER"

    @pytest.mark.parametrize(
        "argval_value, expected_map_val",
        [
            (100, SpecialCases.INTEGER.value),
            (3.14, SpecialCases.FLOAT.value),
            (compile("y=2", "<string>", "exec"), "OBJECT"),
            ("a_const_string", "a_const_string"),
        ],
    )
    def test_map_load_const_number_arg(self, argval_value, expected_map_val):
        mock_instr = MagicMock(spec=dis.Instruction)
        result = map_load_const_number_arg(mock_instr, argval_value, repr(argval_value))
        assert result == expected_map_val

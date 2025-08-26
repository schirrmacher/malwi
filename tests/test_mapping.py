from common.mapping import (
    is_valid_ip,
    is_valid_url,
    is_escaped_hex,
    is_base64,
    is_file_path,
    is_localhost,
    contains_url,
    is_bash_code,
    is_code,
    is_sql,
    is_version,
    is_email,
    is_insecure_protocol,
    is_insecure_url,
)


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


def test_is_bash_code():
    # Test shebang lines (strong indicators)
    assert is_bash_code("#!/bin/bash\necho 'Hello World'")
    assert is_bash_code("#!/usr/bin/bash\nls -la")
    assert is_bash_code("#!/bin/sh\ncd /tmp")
    assert is_bash_code("#!/usr/bin/zsh\ngrep pattern file.txt")

    # Test common bash commands
    assert is_bash_code("ls -la | grep test")
    assert is_bash_code("echo 'Hello' && cd /home")
    assert is_bash_code("rm -rf /tmp/test/*")
    assert is_bash_code("curl https://example.com | jq .")
    assert is_bash_code("sudo chmod 755 script.sh")
    assert is_bash_code("cat file.txt | awk '{print $1}'")
    assert is_bash_code("sed -i 's/old/new/g' file.txt")
    assert is_bash_code("wget https://download.com/file.zip")

    # Test control structures
    assert is_bash_code("if [ -f file.txt ]; then\n  echo 'exists'\nfi")
    assert is_bash_code("for i in $(seq 1 10); do\n  echo $i\ndone")
    assert is_bash_code("while read line; do\n  echo $line\ndone < file.txt")

    # Test variable expansion
    assert is_bash_code("echo $HOME")
    assert is_bash_code("export PATH=$PATH:/usr/local/bin")
    assert is_bash_code("echo ${USER:-default}")
    assert is_bash_code("MY_VAR='test'; echo $MY_VAR")

    # Test command substitution
    assert is_bash_code("echo $(date)")
    assert is_bash_code("files=`ls -la`")
    assert is_bash_code("count=$(wc -l < file.txt)")

    # Test piping and redirection
    assert is_bash_code("ls | head -n 10")
    assert is_bash_code("echo 'test' > output.txt")
    assert is_bash_code("cat file.txt >> append.txt")
    assert is_bash_code("command 2>&1 | tee log.txt")

    # Test command line options
    assert is_bash_code("ls -la --color=auto")
    assert is_bash_code("grep -E 'pattern' file.txt")
    assert is_bash_code("docker run --rm -it ubuntu")

    # Test complex real-world examples
    assert is_bash_code("find . -type f -name '*.log' -exec rm {} \\;")
    assert is_bash_code("ps aux | grep python | awk '{print $2}' | xargs kill")
    assert is_bash_code('for dir in */; do\n  cd "$dir" && git pull && cd ..\ndone')

    # Test edge cases that should NOT be bash code
    assert not is_bash_code("")
    assert not is_bash_code("   ")
    assert not is_bash_code("Hello World")
    assert not is_bash_code("This is just plain text")

    # Note: Threshold parameter removed for fast heuristics

    # Test non-string inputs
    assert not is_bash_code(None)
    assert not is_bash_code(123)
    assert not is_bash_code([])

    # Test multiline bash scripts
    complex_script = """#!/bin/bash
# Backup script
BACKUP_DIR="/backup/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/files.tar.gz" /home/user/
if [ $? -eq 0 ]; then
    echo "Backup successful"
else
    echo "Backup failed" >&2
    exit 1
fi
"""
    assert is_bash_code(complex_script)

    # Test one-liners
    assert is_bash_code("[ -f /etc/passwd ] && echo 'exists' || echo 'not found'")
    assert is_bash_code("find /var/log -name '*.log' -mtime +7 -delete")


def test_is_code():
    # Test Python code
    assert is_code("def hello():\n    print('Hello World')")
    assert is_code("import os\nfrom sys import argv")
    assert is_code("class Person:\n    def __init__(self):\n        pass")
    assert is_code("if x == 5:\n    return True\nelse:\n    return False")
    assert is_code("for i in range(10):\n    print(i)")
    assert is_code("while True:\n    break")
    assert is_code("lambda x: x * 2")

    # Test JavaScript code
    assert is_code("function hello() {\n    console.log('Hello');\n}")
    assert is_code("const x = 5;\nlet y = 10;\nvar z = x + y;")
    assert is_code("if (x === 5) {\n    return true;\n} else {\n    return false;\n}")
    assert is_code("for (let i = 0; i < 10; i++) {\n    console.log(i);\n}")
    assert is_code("const arr = [1, 2, 3];\narr.forEach(x => console.log(x));")

    # Test Java/C++ code
    assert is_code(
        'public class Main {\n    public static void main(String[] args) {\n        System.out.println("Hello");\n    }\n}'
    )
    assert is_code(
        'private int x = 5;\npublic String getName() {\n    return "test";\n}'
    )
    assert is_code(
        '#include <iostream>\nint main() {\n    std::cout << "Hello";\n    return 0;\n}'
    )

    # Test HTML/XML
    assert is_code(
        "<html>\n<head><title>Test</title></head>\n<body>Content</body>\n</html>"
    )
    assert is_code("<div class='test'>\n    <p>Hello</p>\n</div>")
    assert is_code("<?xml version='1.0'?>\n<root><item>data</item></root>")

    # Test JSON (high symbol density)
    assert is_code(
        '{\n    "name": "test",\n    "value": 123,\n    "nested": {\n        "key": "value"\n    }\n}'
    )
    assert is_code('["item1", "item2", {"key": "value"}]')

    # Test CSS
    assert is_code(".class {\n    color: red;\n    margin: 10px;\n}")
    assert is_code("#id { background-color: #fff; }")

    assert is_code("if (a == b && c != d) { return a >= b; }")

    # Test edge cases that should NOT be code
    assert not is_code("")
    assert not is_code("   ")
    assert not is_code("Hello World")
    assert not is_code("A simple sentence.")

    # Test non-string inputs
    assert not is_code(None)
    assert not is_code(123)
    assert not is_code([])

    # Test comments
    assert is_code("// This is a comment\nvar x = 5;")
    assert is_code("# Python comment\nprint('hello')")
    assert is_code("/* Multi-line\n   comment */\nint x;")

    # Test indented code
    assert is_code("if condition:\n    do_something()\n    return value")
    assert is_code('{\n    "key": "value",\n    "number": 42\n}')


def test_is_sql():
    # Test basic SQL operations
    assert is_sql("SELECT * FROM users")
    assert is_sql("SELECT name, email FROM customers WHERE age > 21")
    assert is_sql("INSERT INTO products (name, price) VALUES ('Widget', 9.99)")
    assert is_sql("UPDATE users SET email = 'new@email.com' WHERE id = 1")
    assert is_sql("DELETE FROM orders WHERE status = 'cancelled'")

    # Test table operations (focus on what malware would use)
    assert is_sql("DROP TABLE temp_data")  # Destructive - malware relevant
    assert is_sql("DROP DATABASE old_system")  # Destructive - malware relevant
    assert is_sql("TRUNCATE TABLE logs")  # Destructive - malware relevant

    # Test complex queries with multiple keywords
    assert is_sql(
        "SELECT u.name, COUNT(o.id) FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.name"
    )
    assert is_sql("SELECT * FROM products WHERE price > 100 ORDER BY name")
    assert is_sql(
        "SELECT category, AVG(price) FROM products GROUP BY category HAVING AVG(price) > 50"
    )
    assert is_sql("SELECT * FROM table1 UNION SELECT * FROM table2")
    assert is_sql("SELECT * FROM users WHERE name LIKE '%john%'")

    # Test subqueries
    assert is_sql(
        "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 1000)"
    )
    assert is_sql(
        "SELECT name FROM products WHERE price = (SELECT MAX(price) FROM products)"
    )

    # Test joins
    assert is_sql(
        "SELECT u.name, p.title FROM users u LEFT JOIN posts p ON u.id = p.author_id"
    )
    assert is_sql(
        "SELECT * FROM orders o INNER JOIN customers c ON o.customer_id = c.id"
    )
    assert is_sql("SELECT * FROM table1 t1 RIGHT JOIN table2 t2 ON t1.id = t2.ref_id")

    # Test case insensitivity
    assert is_sql("select * from USERS where ID = 1")
    assert is_sql("Select Name, Email From Customers Order By Name")
    assert is_sql("INSERT into products (NAME, PRICE) values ('test', 10)")

    # Test multi-line SQL
    multiline_sql = """
    SELECT 
        u.name,
        u.email,
        COUNT(o.id) as order_count
    FROM users u
    LEFT JOIN orders o ON u.id = o.user_id
    WHERE u.active = 1
    GROUP BY u.id, u.name, u.email
    ORDER BY order_count DESC
    """
    assert is_sql(multiline_sql)

    # Test SQL with comments
    assert is_sql("SELECT * FROM users -- get all users")
    assert is_sql("/* Get active users */ SELECT * FROM users WHERE active = 1")

    # Test edge cases that should NOT be SQL
    assert not is_sql("")
    assert not is_sql("   ")
    assert not is_sql("Hello World")
    assert not is_sql("This is just plain text")

    # Test non-string inputs
    assert not is_sql(None)
    assert not is_sql(123)
    assert not is_sql([])


def test_is_version():
    # Test simple numbers (should be False - require at least one dot)
    assert not is_version("1")
    assert not is_version("12")
    assert not is_version("0")
    assert not is_version("999")

    # Test basic valid versions
    assert is_version("1.0")
    assert is_version("1.2.3")
    assert is_version("2.0.1")
    assert is_version("10.15.7")  # macOS-style version
    assert is_version("2023.1")  # Year-based version

    # Test pre-release and build versions (PEP 440)
    assert is_version("1.0.0a1")  # Alpha
    assert is_version("1.0.0b2")  # Beta
    assert is_version("1.0.0rc1")  # Release candidate
    assert is_version("2.0.1a1")  # Alpha with patch version
    assert is_version("1.0.0-alpha")  # Alternative alpha format
    assert is_version("1.0.0+build")  # Build version

    # Test versions with 'v' prefix
    assert is_version("v1.0")
    assert is_version("v2.1.3")

    # Test development versions
    assert is_version("1.0.dev0")
    assert is_version("1.2.3.dev456")

    # Test post-release versions
    assert is_version("1.0.post1")
    assert is_version("1.2.3.post2")

    # Test invalid formats (should be False)
    assert not is_version("1.")  # Trailing dot only
    assert not is_version(".1")  # Leading dot only
    assert not is_version("..1")  # Multiple leading dots
    assert not is_version("1..")
    assert not is_version("abc")  # Non-numeric string without dots
    assert not is_version("1.2.3.")  # Trailing dot after version
    assert not is_version("")  # Empty string
    assert not is_version("just.text")  # Text that looks like version but isn't

    # Test edge cases
    assert not is_version(None)  # None input
    assert not is_version(123)  # Non-string input
    assert not is_version([])  # List input

    # Test complex valid versions (PEP 440 allows these)
    assert is_version("1.2.3.4")  # Four components
    assert is_version("1.0.0.0.1")  # Five components
    assert is_version("20.04.1")  # Ubuntu-style version
    assert is_version("3.8.10")  # Python-style version
    assert is_version("1.a.2")  # PEP 440 allows letters in versions

    # Test version with epochs (PEP 440)
    assert is_version("1!1.0.0")  # Epoch version
    assert is_version("2!2.1.3")  # Another epoch version


def test_is_email():
    # Test valid email addresses
    assert is_email("user@example.com")
    assert is_email("test.email@domain.org")
    assert is_email("user+tag@example.co.uk")
    assert is_email("user_name@sub.domain.net")
    assert is_email("123@example.com")  # Numeric username
    assert is_email("user@123domain.com")  # Numeric in domain
    assert is_email("a@b.co")  # Minimal valid email
    assert is_email("user-name@example-domain.com")  # Hyphens
    assert is_email("user%tag@example.com")  # Percent encoding

    # Test valid emails with different TLDs
    assert is_email("user@example.info")
    assert is_email("user@example.museum")  # Longer TLD
    assert is_email("user@example.travel")

    # Test invalid email addresses
    assert not is_email("user@")  # Missing domain
    assert not is_email("@example.com")  # Missing username
    assert not is_email("user@domain")  # Missing TLD
    assert not is_email("user.domain.com")  # Missing @
    assert not is_email("user@@domain.com")  # Double @
    assert not is_email("user@domain..com")  # Double dot
    assert not is_email("user@domain.c")  # TLD too short
    assert not is_email("user @domain.com")  # Space in username
    assert not is_email("user@domain .com")  # Space in domain
    assert not is_email("")  # Empty string
    assert not is_email("   ")  # Only whitespace
    assert not is_email("plaintext")  # No email structure

    # Test edge cases
    assert not is_email(None)  # None input
    assert not is_email(123)  # Non-string input
    assert not is_email([])  # List input

    # Test emails with whitespace (should be trimmed)
    assert is_email(" user@example.com ")  # Leading/trailing whitespace
    assert is_email("\tuser@example.com\n")  # Tab and newline


def test_is_insecure_protocol():
    # Test insecure protocols in URLs
    assert is_insecure_protocol("http://example.com")
    assert is_insecure_protocol("HTTP://EXAMPLE.COM")  # Case insensitive
    assert is_insecure_protocol("http://example.com/path?param=value")
    assert is_insecure_protocol("ftp://files.example.com")
    assert is_insecure_protocol("FTP://FILES.EXAMPLE.COM")
    assert is_insecure_protocol("ftp://user:pass@server.com/path")

    # Test insecure protocols as standalone words
    assert is_insecure_protocol("http")
    assert is_insecure_protocol("ftp")
    assert is_insecure_protocol("telnet")
    assert is_insecure_protocol("ldap")
    assert is_insecure_protocol("smtp")
    assert is_insecure_protocol("pop")
    assert is_insecure_protocol("pop3")
    assert is_insecure_protocol("imap")
    assert is_insecure_protocol("nntp")
    assert is_insecure_protocol("rsh")
    assert is_insecure_protocol("rlogin")
    assert is_insecure_protocol("tftp")
    assert is_insecure_protocol("gopher")

    # Test insecure protocols in text context
    assert is_insecure_protocol("Use http for testing")
    assert is_insecure_protocol("Connect via ftp server")
    assert is_insecure_protocol("telnet connection established")
    assert is_insecure_protocol("smtp server configuration")

    # Test secure protocols (should be False)
    assert not is_insecure_protocol("https://example.com")
    assert not is_insecure_protocol("https")  # Secure variant
    assert not is_insecure_protocol("ftps://files.example.com")
    assert not is_insecure_protocol("ftps")
    assert not is_insecure_protocol("sftp://files.example.com")
    assert not is_insecure_protocol("sftp")
    assert not is_insecure_protocol("ssh://server.example.com")
    assert not is_insecure_protocol("ssh")
    assert not is_insecure_protocol("ldaps://directory.example.com")
    assert not is_insecure_protocol("ldaps")
    assert not is_insecure_protocol("smtps")
    assert not is_insecure_protocol("imaps")
    assert not is_insecure_protocol("pops")

    # Test non-protocol strings
    assert not is_insecure_protocol("example.com")  # Domain only
    assert not is_insecure_protocol("www.example.com")  # Domain only
    assert not is_insecure_protocol("file.txt")  # Filename
    assert not is_insecure_protocol("plaintext")  # Plain text
    assert not is_insecure_protocol("")  # Empty string
    assert not is_insecure_protocol("   ")  # Only whitespace

    # Test edge cases
    assert not is_insecure_protocol(None)  # None input
    assert not is_insecure_protocol(123)  # Non-string input
    assert not is_insecure_protocol([])  # List input

    # Test strings with whitespace (should be trimmed)
    assert is_insecure_protocol(" http://example.com ")
    assert is_insecure_protocol("\tftp\n")

    # Test word boundary matching (avoid false positives)
    assert not is_insecure_protocol(
        "https://example.com"
    )  # 'http' in 'https' should not match
    assert not is_insecure_protocol("webhook")  # 'http' in 'webhook' should not match
    assert not is_insecure_protocol("therapy")  # 'http' substring should not match

    # Test case where insecure protocol appears in text
    assert is_insecure_protocol(
        "This http connection is insecure"
    )  # Should match 'http' as word
    assert is_insecure_protocol("Using ftp protocol")  # Should match 'ftp' as word


def test_is_insecure_url():
    # Test insecure URLs (should be True)
    assert is_insecure_url("http://example.com")
    assert is_insecure_url("HTTP://EXAMPLE.COM")  # Case insensitive
    assert is_insecure_url("http://example.com/path?param=value")
    assert is_insecure_url("ftp://files.example.com")
    assert is_insecure_url("FTP://FILES.EXAMPLE.COM")
    assert is_insecure_url("ftp://user:pass@server.com/path")
    assert is_insecure_url("telnet://server.com:23")
    assert is_insecure_url("ldap://directory.example.com")
    assert is_insecure_url("smtp://mail.example.com:587")
    assert is_insecure_url("pop://mail.example.com:110")
    assert is_insecure_url("pop3://mail.example.com")
    assert is_insecure_url("imap://mail.example.com:143")
    assert is_insecure_url("nntp://news.example.com")
    assert is_insecure_url("rsh://server.example.com")
    assert is_insecure_url("rlogin://server.example.com")
    assert is_insecure_url("tftp://server.example.com")
    assert is_insecure_url("gopher://gopher.example.com")

    # Test secure URLs (should be False)
    assert not is_insecure_url("https://example.com")
    assert not is_insecure_url("ftps://files.example.com")
    assert not is_insecure_url("sftp://files.example.com")
    assert not is_insecure_url("ssh://server.example.com")
    assert not is_insecure_url("ldaps://directory.example.com")
    assert not is_insecure_url("smtps://mail.example.com")
    assert not is_insecure_url("imaps://mail.example.com")
    assert not is_insecure_url("pops://mail.example.com")

    # Test protocol names without URL structure (should be False)
    assert not is_insecure_url("http")  # Just protocol name
    assert not is_insecure_url("ftp")  # Just protocol name
    assert not is_insecure_url("telnet")  # Just protocol name

    # Test text containing protocol names but not URLs (should be False)
    assert not is_insecure_url("Use http for testing")  # Text mentioning protocol
    assert not is_insecure_url("Connect via ftp server")  # Text mentioning protocol
    assert not is_insecure_url(
        "telnet connection established"
    )  # Text mentioning protocol

    # Test non-URL strings (should be False)
    assert not is_insecure_url("example.com")  # Domain only
    assert not is_insecure_url("www.example.com")  # Domain only
    assert not is_insecure_url("file.txt")  # Filename
    assert not is_insecure_url("plaintext")  # Plain text
    assert not is_insecure_url("")  # Empty string
    assert not is_insecure_url("   ")  # Only whitespace

    # Test edge cases
    assert not is_insecure_url(None)  # None input
    assert not is_insecure_url(123)  # Non-string input
    assert not is_insecure_url([])  # List input

    # Test URLs with whitespace (should be trimmed)
    assert is_insecure_url(" http://example.com ")
    assert is_insecure_url("\tftp://files.com\n")

    # Test URLs within text (should match if URL starts with insecure protocol)
    assert not is_insecure_url(
        "Visit http://example.com for more info"
    )  # URL not at start
    assert is_insecure_url("http://example.com is insecure")  # URL at start

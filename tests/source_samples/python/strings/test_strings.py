# Python String Operations Test Suite

# String literals (various quote types)
single_quoted = "Hello world"
double_quoted = "Hello world"
triple_quoted = """Multi-line
string content
here"""
triple_double = """Another multi-line
string with double quotes"""

# Raw strings
raw_string = r"Raw string with \n no escaping"
raw_path = r"C:\Users\name\file.txt"

# F-strings (formatted string literals)
name = "Alice"
age = 30
f_string_basic = f"Hello, {name}!"
f_string_expression = f"{name} is {age} years old"
f_string_complex = f"Next year {name} will be {age + 1}"
f_string_format = f"Pi to 2 decimal places: {3.14159:.2f}"

# String concatenation
concat_plus = "Hello" + " " + "world"
concat_join = "".join(["a", "b", "c"])
concat_format = "{} {}".format("Hello", "world")

# String indexing and slicing
text = "Hello, World!"
first_char = text[0]
last_char = text[-1]
substring = text[7:12]  # "World"
step_slice = text[::2]  # Every other character
reverse_slice = text[::-1]  # Reversed string

# String methods
upper_case = "hello".upper()
lower_case = "HELLO".lower()
title_case = "hello world".title()
capitalized = "hello".capitalize()
stripped = "  hello  ".strip()
left_stripped = "  hello  ".lstrip()
right_stripped = "  hello  ".rstrip()

# String search and replace
text_search = "The quick brown fox"
find_result = text_search.find("quick")
index_result = text_search.index("brown")
count_result = text_search.count("o")
replace_result = text_search.replace("fox", "dog")

# String splitting and joining
csv_data = "apple,banana,cherry"
split_result = csv_data.split(",")
join_result = " | ".join(["a", "b", "c"])
partition_result = "user@domain.com".partition("@")
rsplit_result = "a.b.c.d".rsplit(".", 1)

# String checking methods
is_digit = "123".isdigit()
is_alpha = "abc".isalpha()
is_alnum = "abc123".isalnum()
is_upper = "ABC".isupper()
is_lower = "abc".islower()
starts_with = "hello world".startswith("hello")
ends_with = "hello world".endswith("world")

# String encoding/decoding
unicode_string = "Hello 世界 🌍"
encoded_utf8 = unicode_string.encode("utf-8")
decoded_back = encoded_utf8.decode("utf-8")
encoded_ascii = "hello".encode("ascii")

# String formatting methods
template = "Hello, {}! You have {} messages."
formatted_positional = template.format("Alice", 5)
formatted_named = "Hello, {name}! You have {count} messages.".format(
    name="Bob", count=3
)

# String alignment and padding
centered = "hello".center(20, "*")
left_justified = "hello".ljust(20, "-")
right_justified = "hello".rjust(20, "+")
zero_padded = "42".zfill(5)

# String comparison
str1 = "apple"
str2 = "banana"
comparison = str1 < str2  # Lexicographic comparison
equality = str1 == "apple"
case_insensitive = str1.lower() == "APPLE".lower()

# String interpolation with % formatting (old style)
percent_format = "Hello, %s! You are %d years old." % ("Charlie", 25)
percent_dict = "Hello, %(name)s! You are %(age)d years old." % {
    "name": "Diana",
    "age": 28,
}

# String escaping
escaped_quotes = 'She said "Hello" to me'
escaped_newline = "Line 1\nLine 2\nLine 3"
escaped_tab = "Column1\tColumn2\tColumn3"
escaped_backslash = "Path: C:\\folder\\file.txt"

# String multiplication
repeated = "Ha" * 5
dashes = "-" * 40

# String containment
contains_check = "world" in "Hello world"
not_contains = "xyz" not in "Hello world"

# String translation
translation_table = str.maketrans("aeiou", "12345")
translated = "hello world".translate(translation_table)

# Regular expressions with strings
import re

pattern = r"\d+"
text_with_numbers = "I have 10 apples and 5 oranges"
matches = re.findall(pattern, text_with_numbers)
substituted = re.sub(r"\d+", "X", text_with_numbers)

# String comprehension in lists
words = ["hello", "world", "python"]
uppercase_words = [word.upper() for word in words]
long_words = [word for word in words if len(word) > 5]

# String constants
import string

ascii_letters = string.ascii_letters
digits = string.digits
punctuation = string.punctuation

# Multiline string operations
multiline = """Line 1
Line 2
Line 3"""
lines = multiline.splitlines()
joined_lines = "\n".join(lines)

# String with special characters
special_chars = "Special: !@#$%^&*()_+-=[]{}|;':\",./<>?"
printable_check = all(c in string.printable for c in special_chars)

# String normalization
import unicodedata

accented = "café"
normalized = unicodedata.normalize("NFD", accented)

print("String operations test completed")

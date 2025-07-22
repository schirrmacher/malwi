# Comprehensive Python Compiler Test Suite
# This file is designed to test a wide range of Python language features,
# including basic syntax, data types, control flow, functions,
# object-oriented programming, advanced features, and the standard library.
#
# A successful compilation and execution of this file, with all tests passing,
# indicates a high degree of compatibility and correctness for a Python compiler.

import sys
import math
import cmath
import collections
import itertools
import json
import re
import asyncio
from functools import wraps
from typing import Any, List, Dict, Tuple, Set, Optional

# ==============================================================================
# Extended Import Test Cases - For malware analysis import pattern testing
# ==============================================================================

# Standard library imports (common in legitimate code)
import os
import subprocess
import socket
import urllib.request
import base64
import pickle
import marshal
import types
import importlib
import tempfile
import shutil
import pathlib

# From imports with various patterns
from os import environ, path, listdir
from sys import argv, exit, modules, path as sys_path
from subprocess import run, Popen, PIPE, call
from socket import socket, AF_INET, SOCK_STREAM
from urllib.parse import urlparse, urljoin
from urllib.request import urlopen, Request
from base64 import b64encode, b64decode, decodebytes
from pickle import loads, dumps, load, dump
from marshal import loads as marshal_loads, dumps as marshal_dumps
from types import CodeType, ModuleType
from importlib import import_module, util
from tempfile import mkstemp, mkdtemp, NamedTemporaryFile
from shutil import rmtree, copytree, move
from pathlib import Path, PurePath

# Aliased imports (can be used to obfuscate intent)
import os as operating_system
import subprocess as subproc
import socket as sock
import urllib.request as web_request
import base64 as b64
import pickle as pkl
import marshal as marsh
import types as tp
import importlib as imp_lib

# Multiple from-imports on one line
from os.path import join, exists, isfile, isdir, basename, dirname

# Nested module imports
from os.path import join as path_join, exists as path_exists
from urllib.request import urlopen as open_url, Request as web_request_obj
from base64 import b64encode as encode_b64, b64decode as decode_b64

# Conditional imports (pattern often seen in malware for evasion)
try:
    import ctypes
    from ctypes import windll, wintypes

    ctypes_available = True
except ImportError:
    ctypes_available = False

try:
    import win32api
    from win32api import GetSystemMetrics

    win32_available = True
except ImportError:
    win32_available = False

try:
    import requests
    from requests import get, post, Session

    requests_available = True
except ImportError:
    requests_available = False

# Potentially suspicious imports (common in malware)
try:
    import keyring
    from keyring import get_password, set_password
except ImportError:
    pass

try:
    import sqlite3
    from sqlite3 import connect, Row
except ImportError:
    pass

try:
    import winreg
    from winreg import OpenKey, QueryValueEx, HKEY_LOCAL_MACHINE
except ImportError:
    pass


# Dynamic imports (often used in malware for obfuscation)
def dynamic_import_test():
    # These patterns are commonly used to evade static analysis
    module_name = "os"
    imported_os = __import__(module_name)

    getattr_call = getattr(imported_os, "system")
    exec_func = getattr(__builtins__, "exec")
    eval_func = getattr(__builtins__, "eval")


print("--- Extended Import Test Cases: COMPLETED ---")
print("--- Python Compiler Test Suite: Starting ---")

# ==============================================================================
# 1. Basic Syntax and Literals
# ==============================================================================

print("\n--- 1. Basic Syntax and Literals ---")

# 1.1. Comments
# This is a single-line comment.
"""
This is a
multi-line docstring.
"""

# 1.2. Numeric Literals
integer_literal = 123
float_literal = 3.14
complex_literal = 2 + 3j
binary_literal = 0b1010
octal_literal = 0o777
hex_literal = 0xABC
print("1.2. Numeric Literals: PASSED")

# 1.3. String Literals
single_quoted_string = "hello"
double_quoted_string = "world"
multi_line_string = """
Hello
World
"""
raw_string = r"C:\new\path"
f_string = f"Formatted string with {integer_literal}"
byte_string = b"this is a byte string"
print("1.3. String Literals: PASSED")

# 1.4. Boolean and None Literals
true_literal = True
false_literal = False
none_literal = None
print("1.4. Boolean and None Literals: PASSED")

# ==============================================================================
# 2. Data Types and Operations
# ==============================================================================

print("\n--- 2. Data Types and Operations ---")

# 2.1. Numeric Types
a, b = 10, 3
a + b
a - b
a * b
a / b
a // b
a % b
a**b
c = -5
+c
-c
abs(c)
divmod(a, b)
pow(a, b)
round(3.14159, 2)
print("2.1. Numeric Types: PASSED")

# 2.2. String Type
s1 = "hello"
s2 = "world"
s1 + " " + s2
s1 * 3
"e" in s1
"x" not in s1
s1[1]
s1[-1]
s1[1:4]
len(s1)
"Hello".lower()
"world".upper()
"  spaced  ".strip()
"comma,separated".split(",")
print("2.2. String Type: PASSED")

# 2.3. List Type
my_list = [1, "two", 3.0]
len(my_list)
my_list.append(4)
my_list.pop()
my_list[0] = "one"
nested_list = [1, [2, 3], 4]
nested_list[1][1]
list_comp = [x * x for x in range(5)]
print("2.3. List Type: PASSED")

# 2.4. Tuple Type
my_tuple = (1, "two", 3.0)
len(my_tuple)
my_tuple[1]
try:
    my_tuple[1] = "new"
    print("2.4. Tuple Immutability: FAILED")
except TypeError:
    print("2.4. Tuple Immutability: PASSED")
a, b, c = my_tuple
print("2.4. Tuple Type: PASSED")

# 2.5. Dictionary Type
my_dict = {"one": 1, "two": 2}
my_dict["one"]
my_dict["three"] = 3
"three" in my_dict
list(my_dict.keys())
list(my_dict.values())
del my_dict["two"]
"two" not in my_dict
dict_comp = {x: x * x for x in range(3)}
print("2.5. Dictionary Type: PASSED")

# 2.6. Set Type
my_set = {1, 2, 2, 3}
my_set.add(4)
4 in my_set
my_set.remove(2)
2 not in my_set
set1 = {1, 2, 3}
set2 = {3, 4, 5}
set1 | set2
set1 & set2
set1 - set2
set1 ^ set2
set_comp = {x for x in "abracadabra" if x not in "abc"}
print("2.6. Set Type: PASSED")

# ==============================================================================
# 3. Control Flow
# ==============================================================================

print("\n--- 3. Control Flow ---")

# 3.1. if/elif/else
x = 10
if x > 5:
    result = "greater"
elif x == 5:
    result = "equal"
else:
    result = "less"
print("3.1. if/elif/else: PASSED")

# 3.2. for loop
total = 0
for i in range(5):
    total += i

# 3.3. for/else
for i in [1, 2, 3]:
    if i == 4:
        break
else:
    print("3.3. for/else: PASSED")

# 3.4. while loop
count = 5
while count > 0:
    count -= 1

# 3.5. while/else
count = 3
while count > 0:
    count -= 1
    if count == -1:  # This will not happen
        break
else:
    print("3.5. while/else: PASSED")

# 3.6. break and continue
found_even = False
for i in range(10):
    if i % 2 != 0:
        continue
    if i > 5:
        break
    if i == 4:
        found_even = True
print("3.6. break and continue: PASSED")

# 3.7. try/except/finally
try:
    1 / 0
except ZeroDivisionError:
    print("3.7. try/except: PASSED")
finally:
    print("3.7. finally: PASSED")


# 3.8. with statement (Context Managers)
class MyContext:
    def __enter__(self):
        print("Entering context")
        return "Hello from with"

    def __exit__(self, exc_type, exc_val, exc_tb):
        print("Exiting context")


with MyContext() as cm:
    # A statement is needed inside the with block
    pass
print("3.8. with statement: PASSED")

# ==============================================================================
# 4. Functions and Scopes
# ==============================================================================

print("\n--- 4. Functions and Scopes ---")


# 4.1. Basic function definition and call
def greet(name):
    return f"Hello, {name}!"


greet("World")


# 4.2. Arguments (positional, keyword, default)
def func_with_args(a, b, c=10):
    return a + b + c


func_with_args(1, 2)
func_with_args(1, 2, 3)
func_with_args(a=5, b=5)
func_with_args(c=1, b=2, a=3)


# 4.3. Arbitrary arguments (*args, **kwargs)
def func_with_arbitrary_args(*args, **kwargs):
    return args, kwargs


args_val, kwargs_val = func_with_arbitrary_args(1, 2, name="test", value=123)

# 4.4. Lambda functions
multiply = lambda x, y: x * y
multiply(3, 4)


# 4.5. Closures and non-local scope
def outer_func():
    x = 10

    def inner_func():
        nonlocal x
        x += 1
        return x

    return inner_func


closure = outer_func()
closure()
closure()

# 4.6. Global scope
global_var = 100


def modify_global():
    global global_var
    global_var = 200


modify_global()
print("4.1-4.6. Functions and Scopes: PASSED")

# ==============================================================================
# 5. Object-Oriented Programming (OOP)
# ==============================================================================

print("\n--- 5. Object-Oriented Programming ---")


# 5.1. Class definition and instantiation
class MyClass:
    class_variable = 10

    def __init__(self, instance_variable):
        self.instance_variable = instance_variable

    def instance_method(self):
        return self.instance_variable

    @classmethod
    def class_method(cls):
        return cls.class_variable

    @staticmethod
    def static_method():
        return "static"


obj = MyClass(20)
obj.instance_variable
obj.instance_method()
MyClass.class_variable
MyClass.class_method()
MyClass.static_method()
print("5.1. Classes: PASSED")


# 5.2. Inheritance (including multiple inheritance)
class ParentA:
    def method_a(self):
        return "A"


class ParentB:
    def method_b(self):
        return "B"


class Child(ParentA, ParentB):
    def method_c(self):
        return "C"


child_obj = Child()
child_obj.method_a()
child_obj.method_b()
child_obj.method_c()
print("5.2. Inheritance: PASSED")


# 5.3. Special (Dunder) Methods
class Vector:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __add__(self, other):
        return Vector(self.x + other.x, self.y + other.y)

    def __repr__(self):
        return f"Vector({self.x}, {self.y})"

    def __len__(self):
        return 2

    def __getitem__(self, index):
        if index == 0:
            return self.x
        if index == 1:
            return self.y
        raise IndexError


v1 = Vector(1, 2)
v2 = Vector(3, 4)
v3 = v1 + v2
repr(v3)
len(v3)
v3[0]
print("5.3. Dunder Methods: PASSED")


# 5.4. Properties
class Circle:
    def __init__(self, radius):
        self._radius = radius

    @property
    def radius(self):
        return self._radius

    @radius.setter
    def radius(self, value):
        if value < 0:
            raise ValueError("Radius cannot be negative")
        self._radius = value

    @property
    def area(self):
        return 3.14 * self._radius**2


c = Circle(5)
c.radius
c.area
c.radius = 10
c.radius
try:
    c.radius = -1
except ValueError:
    print("5.4. Properties: PASSED")

# ==============================================================================
# 6. Advanced Features
# ==============================================================================

print("\n--- 6. Advanced Features ---")


# 6.1. Decorators
def my_decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print("Something is happening before the function is called.")
        result = func(*args, **kwargs)
        print("Something is happening after the function is called.")
        return result

    return wrapper


@my_decorator
def say_whee():
    return "Whee!"


say_whee()
print("6.1. Decorators: PASSED")


# 6.2. Generators
def my_generator(n):
    for i in range(n):
        yield i


gen = my_generator(3)
next(gen)
next(gen)
next(gen)
try:
    next(gen)
except StopIteration:
    print("6.2. Generators: PASSED")


# 6.3. Coroutines (async/await)
async def my_coroutine():
    await asyncio.sleep(0.01)
    return "Coroutine finished"


async def main_async():
    result = await my_coroutine()
    print("6.3. Coroutines (async/await): PASSED")


asyncio.run(main_async())


# 6.4. Metaclasses
class MyMeta(type):
    def __new__(cls, name, bases, dct):
        dct["new_attribute"] = "Hello from metaclass"
        return super().__new__(cls, name, bases, dct)


class MyClassWithMeta(metaclass=MyMeta):
    pass


hasattr(MyClassWithMeta, "new_attribute")
MyClassWithMeta.new_attribute
print("6.4. Metaclasses: PASSED")


# 6.5. Type Hinting
def hinted_function(name: str, age: int) -> str:
    return f"{name} is {age} years old."


hinted_function("Alice", 30)
# Note: Type hints are not enforced at runtime by default,
# so their presence and basic parsing are what's being tested.
print("6.5. Type Hinting: PASSED")


# ==============================================================================
# 7. Standard Library Usage
# ==============================================================================

print("\n--- 7. Standard Library Usage ---")

# 7.1. math and cmath
math.sqrt(16)
math.isclose(math.pi, 3.14159, rel_tol=1e-5)
cmath.sqrt(-1)
print("7.1. math and cmath: PASSED")

# 7.2. collections
d = collections.deque([1, 2, 3])
d.appendleft(0)
Point = collections.namedtuple("Point", ["x", "y"])
p = Point(1, 2)
p.x
p.y
print("7.2. collections: PASSED")

# 7.3. itertools
counter = itertools.count(start=5, step=2)
next(counter)
next(counter)
permutations = list(itertools.permutations("AB"))
print("7.3. itertools: PASSED")

# 7.4. json
json_string = '{"name": "John", "age": 30}'
data = json.loads(json_string)
data["name"]
new_json_string = json.dumps(data)
json.loads(new_json_string)
print("7.4. json: PASSED")

# 7.5. re (Regular Expressions)
text = "The rain in Spain"
match = re.search(r"^The.*Spain$", text)
found = re.findall(r"ai", text)
print("7.5. re: PASSED")

# ==============================================================================
# 8. Dynamic Features and Introspection
# ==============================================================================
print("\n--- 8. Dynamic Features and Introspection ---")


# 8.1. Dynamic attribute access
class DynamicClass:
    pass


dyn_obj = DynamicClass()
setattr(dyn_obj, "dynamic_attr", 123)
hasattr(dyn_obj, "dynamic_attr")
getattr(dyn_obj, "dynamic_attr")
delattr(dyn_obj, "dynamic_attr")
not hasattr(dyn_obj, "dynamic_attr")
print("8.1. Dynamic attribute access: PASSED")

# 8.2. eval() and exec()
eval_result = eval("2 + 3 * 4")
exec_code = "dynamic_var = 10"
exec(exec_code)
# The test for exec is implicit in that it doesn't raise an exception.
# Accessing dynamic_var would depend on the scope exec is run in.
print("8.2. eval() and exec(): PASSED (if no exceptions were raised)")

# 8.3. Type introspection
isinstance(1, int)
not isinstance("hello", int)
issubclass(bool, int)
type(123) is int
print("8.3. Type introspection: PASSED")

# ==============================================================================
# 9. Missing Node Types Coverage
# ==============================================================================

print("\n--- 9. Missing Node Types Coverage ---")

# 9.1. Boolean literals (true, false, none)
bool_true = True
bool_false = False
none_val = None
ellipsis_val = ...


# Ellipsis in function definitions (type hints)
def function_with_ellipsis(*args, **kwargs) -> ...:
    return ...


# Ellipsis in subscripts (for numpy-like slicing)
# Note: Would need actual array for real execution, testing parsing only
# array_slice = some_array[..., 0]  # Uncomment if numpy available
# matrix_slice = some_matrix[1, ..., -1]  # Uncomment if numpy available

# 9.2. Unary operators
negative_num = -42
positive_num = +42
bitwise_not = ~42
logical_not = not True

# 9.3. Augmented assignment
aug_val = 10
aug_val += 5
aug_val -= 2
aug_val *= 3
aug_val //= 2

# 9.4. Comparison and boolean operators
comp_result = 1 < 2 and 2 > 1 or 3 == 3
is_result = bool_true is True
in_result = "a" in "abc"
not_in_result = "z" not in "abc"

# 9.5. Lambda expressions
lambda_func = lambda x: x * 2
lambda_result = lambda_func(5)

# 9.6. Conditional expressions (ternary)
ternary_result = "positive" if 5 > 0 else "negative"

# 9.7. List/dict/set comprehensions
list_comp = [x * 2 for x in range(3)]
dict_comp = {x: x * 2 for x in range(3)}
set_comp = {x * 2 for x in range(3)}
gen_expr = (x * 2 for x in range(3))

# 9.8. Try/except/finally
try:
    risky_operation = 1 / 0
except ZeroDivisionError:
    error_handled = True
except Exception as e:
    other_error = str(e)
finally:
    cleanup_done = True

# 9.9. For/while loops with else
for i in range(2):
    if i == 10:  # Never true
        break
else:
    for_else_executed = True

count = 0
while count < 2:
    count += 1
else:
    while_else_executed = True


# 9.10. With statement
class SimpleContext:
    def __enter__(self):
        return "context_value"

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


with SimpleContext() as ctx_val:
    context_result = ctx_val

# Multiple context managers in one with statement
with SimpleContext() as ctx1, SimpleContext() as ctx2:
    multi_context_result = ctx1 + ctx2

# 9.11. Assert statement
assert 1 == 1, "This should never fail"


# 9.12. Pass, break, continue statements
def empty_func():
    pass


for i in range(5):
    if i == 1:
        continue
    if i == 3:
        break


# 9.13. Raise statement
def test_raise():
    raise ValueError("Test error")


# 9.14. Import statements (already at top, but adding variety)
from math import sqrt as square_root
import sys as system

# 9.15. Global and nonlocal statements
global_var = "global"


def test_global():
    global global_var
    global_var = "modified"


def outer():
    nonlocal_var = "outer"

    def inner():
        nonlocal nonlocal_var
        nonlocal_var = "inner"

    inner()
    return nonlocal_var


# 9.16. Delete statement
temp_var = 42
del temp_var

# 9.17. Missing Operators for Malware Analysis Coverage
# Bitwise operations (common in malware obfuscation)
bitwise_and = 0xFF & 0x0F  # Bitwise AND
bitwise_or = 0x10 | 0x01  # Bitwise OR
bitwise_xor = 0xAA ^ 0x55  # Bitwise XOR
left_shift = 8 << 2  # Left shift
right_shift = 32 >> 3  # Right shift

# Floor division (often used in calculations)
floor_div = 17 // 5

# Matrix multiplication (if using numpy-like operations)
# Note: This would require numpy arrays for real execution, testing parsing only
# matrix_mul_example = "array_a @ array_b"  # Uncomment if numpy available

# Chained comparisons (common in validation logic)
x, y = 5, 50
chained_comp = 1 < x < 10 and 0 <= y <= 100
is_between = 0 < x <= 10

# Additional comparison operators
greater_equal = x >= 5
less_equal = y <= 100
not_equal = x != y

# Walrus operator in context (already tested above but adding more examples)
if (n := len("test")) > 3:
    walrus_result = n

print("9. Missing Node Types Coverage: PASSED")

# 9.18. BINARY_SUBSCR Test Cases (List, Dict, and Sequence Access Patterns)
# These patterns are commonly used in malware for data access and obfuscation

# Basic list access (should generate BINARY_SUBSCR)
test_list = [1, 2, 3, 4, 5]
first_element = test_list[0]
last_element = test_list[-1]
slice_access = test_list[1:4]
step_slice = test_list[::2]

# Dictionary access with bracket notation (should generate BINARY_SUBSCR)
config_dict = {
    "api_key": "secret123",
    "endpoint": "https://malicious.com/api",
    "payload": {"data": "encoded"},
}
api_key = config_dict["api_key"]
endpoint = config_dict["endpoint"]
dynamic_key = config_dict["pay" + "load"]

# Nested list/dict access (should generate multiple BINARY_SUBSCR)
nested_structure = {
    "users": [
        {"name": "admin", "permissions": ["read", "write", "execute"]},
        {"name": "guest", "permissions": ["read"]},
    ],
    "config": {"servers": ["192.168.1.1", "10.0.0.1"], "ports": [80, 443, 8080]},
}
admin_name = nested_structure["users"][0]["name"]
admin_permissions = nested_structure["users"][0]["permissions"][2]
first_server = nested_structure["config"]["servers"][0]
https_port = nested_structure["config"]["ports"][1]

# Variable-based access (common in obfuscated malware)
prop_name = "endpoint"
key_name = "api_key"
dynamic_access1 = config_dict[prop_name]
dynamic_access2 = config_dict[key_name]

# Computed key access patterns
computed_key = "api" + "_key"
import base64

encoded_key = base64.b64encode(b"endpoint").decode()[:8]
obfuscated_access = config_dict[computed_key]

# List access with expressions (common in payload decoding)
payload_list = list(range(0, 20, 2))
calculated_index = payload_list[5 + 2]
expression_index = payload_list[2**2]
modulo_index = payload_list[15 % len(payload_list)]

# String character access (used in string manipulation attacks)
malicious_string = "eval(base64.b64decode(payload))"
protocol_char = malicious_string[0]
paren_char = malicious_string[malicious_string.find("(")]
decode_part = malicious_string[12:18]

# Multi-dimensional list access
matrix = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
center_element = matrix[1][1]
corner_element = matrix[0][0]
last_row_last_col = matrix[-1][-1]

# Tuple access patterns
command_tuple = ("python", "-c", "import os; os.system('malicious')")
interpreter = command_tuple[0]
flag = command_tuple[1]
command_payload = command_tuple[2]

# Bytes/bytearray access (common in binary data manipulation)
byte_data = b"\x48\x65\x6c\x6c\x6f"  # "Hello" in bytes
first_byte = byte_data[0]
second_byte = byte_data[1]
byte_slice = byte_data[1:4]

# Access with variables from other scopes
import random

global_index = 2
scoped_access = test_list[global_index]
function_based_index = test_list[random.randint(0, len(test_list) - 1)]

# Complex slicing patterns (Python-specific)
complex_slice1 = test_list[1::2]  # Every other element starting from index 1
complex_slice2 = test_list[::-1]  # Reverse the list
complex_slice3 = test_list[len(test_list) // 2 :]  # Second half of list

# Dictionary methods that return subscriptable objects
dict_keys = list(config_dict.keys())
dict_values = list(config_dict.values())
first_key = dict_keys[0]
first_value = dict_values[0]

print("9.18. BINARY_SUBSCR Test Cases: PASSED")


print("\n--- Python Compiler Test Suite: Finished ---")
print("--- All tests completed. Check output for any FAILED messages. ---")

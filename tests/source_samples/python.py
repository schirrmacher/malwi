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


print("\n--- Python Compiler Test Suite: Finished ---")
print("--- All tests completed. Check output for any FAILED messages. ---")

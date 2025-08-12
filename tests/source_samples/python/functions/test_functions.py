# Python Functions and Scopes Test Suite

# Basic function definition and call
def greet(name):
    return f"Hello, {name}!"


greet("World")


# Arguments (positional, keyword, default)
def func_with_args(a, b, c=10):
    return a + b + c


func_with_args(1, 2)
func_with_args(1, 2, 3)
func_with_args(a=5, b=5)
func_with_args(c=1, b=2, a=3)


# Arbitrary arguments (*args, **kwargs)
def func_with_arbitrary_args(*args, **kwargs):
    return args, kwargs


args_val, kwargs_val = func_with_arbitrary_args(1, 2, name="test", value=123)

# Comprehensive KW_NAMES test cases
print("Testing KW_NAMES generation", end="", flush=True)  # KW_NAMES
open("test.txt", mode="w", encoding="utf-8")  # KW_NAMES
sorted([3, 1, 4, 2], key=lambda x: x, reverse=True)  # KW_NAMES
dict(name="test", value=42, flag=True)  # KW_NAMES
max([1, 2, 3], default=0)  # KW_NAMES
min([1, 2, 3], default=0)  # KW_NAMES
list(range(0, 10, 2))  # Alternative without keyword args
"Hello {name}".format(name="World")  # KW_NAMES

# Lambda functions
multiply = lambda x, y: x * y
multiply(3, 4)


# Closures and non-local scope
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

# Global scope
global_var = 100


def modify_global():
    global global_var
    global_var = 200


modify_global()


# Nested functions
def outer():
    nonlocal_var = "outer"

    def inner():
        nonlocal nonlocal_var
        nonlocal_var = "inner"

    inner()
    return nonlocal_var


# Decorators
def my_decorator(func):
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        return result

    return wrapper


@my_decorator
def say_whee():
    return "Whee!"


say_whee()


# Generators
def my_generator(n):
    for i in range(n):
        yield i


gen = my_generator(3)
next(gen)
next(gen)
next(gen)


# Type hints
def hinted_function(name: str, age: int) -> str:
    return f"{name} is {age} years old."


hinted_function("Alice", 30)

print("Functions and scopes test completed")

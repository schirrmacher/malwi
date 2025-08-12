# Python Advanced Features Test Suite

import asyncio
from functools import wraps


# Coroutines (async/await)
async def my_coroutine():
    await asyncio.sleep(0.01)
    return "Coroutine finished"


async def main_async():
    result = await my_coroutine()
    return result


asyncio.run(main_async())

# List/dict/set comprehensions
list_comp = [x * 2 for x in range(3)]
dict_comp = {x: x * 2 for x in range(3)}
set_comp = {x * 2 for x in range(3)}
gen_expr = (x * 2 for x in range(3))

# Nested comprehensions
matrix = [[i * j for j in range(3)] for i in range(3)]

# Comprehensions with conditions
evens = [x for x in range(10) if x % 2 == 0]
filtered_dict = {k: v for k, v in {"a": 1, "b": 2, "c": 3}.items() if v > 1}

# Tuple unpacking patterns
a, b = (10, 20)
x, y, z = [1, 2, 3]
first, *rest = [1, 2, 3, 4, 5]
a, *middle, b = [1, 2, 3, 4, 5]
x, y, *rest = range(10)

# Conditional expressions (ternary)
ternary_result = "positive" if 5 > 0 else "negative"

# Walrus operator
if (n := len([1, 2, 3])) > 2:
    walrus_result = n

# Delete operations
temp_var = 42
del temp_var

lst = [1, 2, 3, 4, 5]
del lst[0]
del lst[1:3]

d = {"a": 1, "b": 2}
del d["a"]

# Slice operations
lst = [0, 1, 2, 3, 4, 5]
a = lst[1:4]
b = lst[::2]
c = lst[::-1]
lst[1:3] = [10, 20]

# Complex slicing
complex_slice1 = lst[1::2]  # Every other element starting from index 1
complex_slice2 = lst[::-1]  # Reverse the list
complex_slice3 = lst[len(lst) // 2 :]  # Second half of list

print("Advanced features test completed")

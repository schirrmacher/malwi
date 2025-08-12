# Python Control Flow Test Suite

# if/elif/else statements
x = 10
if x > 5:
    result = "greater"
elif x == 5:
    result = "equal"
else:
    result = "less"

# Nested if statements
x, y = 5, 10
if x > 0:
    if y > 0:
        result = "both positive"
    else:
        result = "x positive, y not"
else:
    result = "x not positive"

# for loop
total = 0
for i in range(5):
    total += i

# for/else
for i in [1, 2, 3]:
    if i == 4:
        break
else:
    pass  # Loop completed without break

# Nested for loops
for i in range(3):
    for j in range(3):
        pass

# while loop
count = 5
while count > 0:
    count -= 1

# while/else
count = 3
while count > 0:
    count -= 1
    if count == -1:  # This will not happen
        break
else:
    pass  # Loop completed without break

# break and continue
found_even = False
for i in range(10):
    if i % 2 != 0:
        continue
    if i > 5:
        break
    if i == 4:
        found_even = True

# try/except/finally
try:
    1 / 0
except ZeroDivisionError:
    pass  # Handle division by zero
finally:
    pass  # Always executes

# Multiple except clauses
try:
    risky_operation = 1 / 0
except ZeroDivisionError:
    error_handled = True
except Exception as e:
    other_error = str(e)
finally:
    cleanup_done = True


# with statement (Context Managers)
class MyContext:
    def __enter__(self):
        return "Hello from with"

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


with MyContext() as cm:
    pass

# Multiple context managers
with MyContext() as ctx1, MyContext() as ctx2:
    multi_context_result = ctx1 + ctx2

# Assert statement
assert 1 == 1, "This should never fail"


# Pass statement
def empty_func():
    pass


print("Control flow test completed")

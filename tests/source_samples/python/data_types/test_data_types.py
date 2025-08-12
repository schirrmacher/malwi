# Python Data Types and Operations Test Suite

# Numeric Types and Operations
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

# String Type and Operations
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

# List Type and Operations
my_list = [1, "two", 3.0]
len(my_list)
my_list.append(4)
my_list.pop()
my_list[0] = "one"
nested_list = [1, [2, 3], 4]
nested_list[1][1]
list_comp = [x * x for x in range(5)]

# Tuple Type and Operations
my_tuple = (1, "two", 3.0)
len(my_tuple)
my_tuple[1]
try:
    my_tuple[1] = "new"
except TypeError:
    pass  # Expected - tuples are immutable
a, b, c = my_tuple

# Dictionary Type and Operations
my_dict = {"one": 1, "two": 2}
my_dict["one"]
my_dict["three"] = 3
"three" in my_dict
list(my_dict.keys())
list(my_dict.values())
del my_dict["two"]
"two" not in my_dict
dict_comp = {x: x * x for x in range(3)}

# Set Type and Operations
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

print("Data types and operations test completed")

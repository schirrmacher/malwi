# Python Operators and Binary Operations Test Suite

# Arithmetic operators
a, b = 10, 3
a + b
a - b
a * b
a / b
a // b  # Floor division
a % b
a**b

# Unary operators
negative_num = -42
positive_num = +42
bitwise_not = ~42
logical_not = not True

# Bitwise operations (common in malware obfuscation)
bitwise_and = 0xFF & 0x0F  # Bitwise AND
bitwise_or = 0x10 | 0x01  # Bitwise OR
bitwise_xor = 0xAA ^ 0x55  # Bitwise XOR
left_shift = 8 << 2  # Left shift
right_shift = 32 >> 3  # Right shift

# Comparison operators
x, y = 5, 50
x < y
x > 0
x <= 10
y >= 50
x == 5
x != y

# Chained comparisons
chained_comp = 1 < x < 10 and 0 <= y <= 100
is_between = 0 < x <= 10

# Boolean operators
comp_result = 1 < 2 and 2 > 1 or 3 == 3
is_result = True is True
in_result = "a" in "abc"
not_in_result = "z" not in "abc"

# Augmented assignment
aug_val = 10
aug_val += 5
aug_val -= 2
aug_val *= 3
aug_val //= 2
aug_val **= 2
aug_val &= 0xFF

# BINARY_SUBSCR test cases
test_list = [1, 2, 3, 4, 5]
first_element = test_list[0]
last_element = test_list[-1]
slice_access = test_list[1:4]
step_slice = test_list[::2]

# Dictionary subscript access
config_dict = {
    "api_key": "secret123",
    "endpoint": "https://example.com/api",
    "payload": {"data": "encoded"},
}
api_key = config_dict["api_key"]
endpoint = config_dict["endpoint"]
dynamic_key = config_dict["pay" + "load"]

# Nested access
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

# STORE_SUBSCR test cases
store_obj = {}
store_arr = []

# Basic subscript assignments
store_obj["key1"] = "value1"
store_obj["key2"] = "value2"

# Variable key assignment
store_key = "dynamicKey"
store_obj[store_key] = "dynamicValue"

# List assignment
store_arr.extend([None, None, None])
store_arr[0] = "first"
store_arr[1] = "second"
store_arr[2] = "third"

print("Operators and binary operations test completed")

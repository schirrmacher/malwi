# Python Standard Library Usage Test Suite

import math
import cmath
import collections
import itertools
import json
import re

# math and cmath
math.sqrt(16)
math.isclose(math.pi, 3.14159, rel_tol=1e-5)
cmath.sqrt(-1)

# collections
d = collections.deque([1, 2, 3])
d.appendleft(0)
Point = collections.namedtuple("Point", ["x", "y"])
p = Point(1, 2)
p.x
p.y

# itertools
counter = itertools.count(start=5, step=2)
next(counter)
next(counter)
permutations = list(itertools.permutations("AB"))

# json
json_string = '{"name": "John", "age": 30}'
data = json.loads(json_string)
data["name"]
new_json_string = json.dumps(data)
json.loads(new_json_string)

# re (Regular Expressions)
text = "The rain in Spain"
match = re.search(r"^The.*Spain$", text)
found = re.findall(r"ai", text)

print("Standard library usage test completed")

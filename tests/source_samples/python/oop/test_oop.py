# Python Object-Oriented Programming Test Suite

# Class definition and instantiation
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


# Inheritance (including multiple inheritance)
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


# Special (Dunder) Methods
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


# Properties
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
    pass


# Metaclasses
class MyMeta(type):
    def __new__(cls, name, bases, dct):
        dct["new_attribute"] = "Hello from metaclass"
        return super().__new__(cls, name, bases, dct)


class MyClassWithMeta(metaclass=MyMeta):
    pass


hasattr(MyClassWithMeta, "new_attribute")
MyClassWithMeta.new_attribute

print("Object-oriented programming test completed")

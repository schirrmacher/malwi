# Python Dynamic Features and Introspection Test Suite

# Dynamic attribute access
class DynamicClass:
    pass


dyn_obj = DynamicClass()
setattr(dyn_obj, "dynamic_attr", 123)
hasattr(dyn_obj, "dynamic_attr")
getattr(dyn_obj, "dynamic_attr")
delattr(dyn_obj, "dynamic_attr")
not hasattr(dyn_obj, "dynamic_attr")

# eval() and exec()
eval_result = eval("2 + 3 * 4")
exec_code = "dynamic_var = 10"
exec(exec_code)

# Type introspection
isinstance(1, int)
not isinstance("hello", int)
issubclass(bool, int)
type(123) is int

# Global variable operations
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


# Global variable shadowing
shadow_var = "global shadow"


def shadow_test():
    shadow_var = "local shadow"

    def inner_shadow():
        nonlocal shadow_var
        shadow_var = "modified local"

    def inner_global_shadow():
        global shadow_var
        shadow_var = "modified global"

    inner_shadow()
    local_result = shadow_var
    inner_global_shadow()
    return local_result


print("Dynamic features and introspection test completed")

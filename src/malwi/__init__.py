"""malwi - AI Python Malware Scanner."""

from malwi._version import __version__


def __getattr__(name):
    """Lazy import to avoid circular import issues."""
    if name == "MalwiReport":
        from common.malwi_report import MalwiReport

        return MalwiReport
    elif name == "MalwiObject":
        from common.malwi_object import MalwiObject

        return MalwiObject
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = ["__version__", "MalwiReport", "MalwiObject"]

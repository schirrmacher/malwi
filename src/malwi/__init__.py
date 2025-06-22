"""malwi - AI Python Malware Scanner."""

from malwi._version import __version__


def __getattr__(name):
    """Lazy import to avoid circular import issues."""
    if name == "process_files":
        from research.disassemble_python import process_files

        return process_files
    elif name == "MalwiReport":
        from research.disassemble_python import MalwiReport

        return MalwiReport
    elif name == "MalwiObject":
        from research.disassemble_python import MalwiObject

        return MalwiObject
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = ["__version__", "process_files", "MalwiReport", "MalwiObject"]

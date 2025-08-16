import json
import logging
import pathlib
import sys
import shutil
from pathlib import Path
from typing import Dict, Any


def read_json_from_file(filepath: pathlib.Path) -> Dict[str, Any]:
    """Reads and parses JSON data from a file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    except FileNotFoundError:
        logging.error(f"Mapping file not found: {filepath}")
    except json.JSONDecodeError:
        logging.error(f"Could not decode JSON from file {filepath}. Check format.")
    except Exception as e:
        logging.error(f"An unexpected error occurred reading {filepath}: {e}")
    # Return empty dict on error to allow script to potentially continue with defaults/empty mappings
    return {}


def copy_file(file_path: Path, base_input_path: Path, move_dir: Path) -> None:
    """
    Copy a file to the move directory while preserving folder structure.

    Args:
        file_path: Path to the file to copy
        base_input_path: Base input path that was scanned (to calculate relative path)
        move_dir: Directory to copy files to
    """
    try:
        # Calculate relative path from the base input path
        if base_input_path.is_file():
            # If scanning a single file, just use the filename
            relative_path = file_path.name
        else:
            # If scanning a directory, preserve the folder structure
            relative_path = file_path.relative_to(base_input_path)

        # Create the destination path
        dest_path = move_dir / relative_path

        # Create parent directories if they don't exist
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Copy the file
        shutil.copy2(file_path, dest_path)

    except Exception as e:
        # Don't fail the operation if copying fails, just log it
        print(f"Warning: Failed to copy {file_path}: {e}", file=sys.stderr)

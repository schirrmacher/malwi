import json
import logging
import pathlib
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

"""
CSV Writer module for AST to Malwicode compilation output.
"""

import csv
from pathlib import Path
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from .ast_to_malwicode import CodeObject


class CSVWriter:
    """Handles CSV output operations for AST to Malwicode compilation."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.file_handle = None
        self.writer = None
        self._initialize_file()

    def _initialize_file(self):
        """Initialize CSV file with headers if needed."""
        file_exists_before_open = self.file_path.is_file()
        is_empty = not file_exists_before_open or self.file_path.stat().st_size == 0

        self.file_handle = open(
            self.file_path, "a", newline="", encoding="utf-8", errors="replace"
        )
        self.writer = csv.writer(self.file_handle)

        if is_empty:
            self.writer.writerow(["tokens", "hash", "language", "filepath"])

    def write_code_objects(self, code_objects: List["CodeObject"]) -> None:
        """Write CodeObject data to CSV."""
        for obj in code_objects:
            self.writer.writerow(
                [
                    obj.to_string(one_line=True, mapped=True),
                    obj.to_hash(),
                    obj.language,
                    obj.path,
                ]
            )

    def close(self):
        """Close the CSV file."""
        if self.file_handle:
            self.file_handle.close()

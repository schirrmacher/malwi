"""
CodeObject class for malwi AST representation.

This module contains the CodeObject class which represents a compiled piece of code,
including its bytecode, source code, and location information.
"""

import hashlib
from pathlib import Path
from typing import List, Tuple, TYPE_CHECKING

from common.mapping import COMMON_TARGET_FILES, SpecialCases

if TYPE_CHECKING:
    from common.bytecode import Instruction


class CodeObject:
    """
    A container for a compiled piece of code, including its bytecode,
    source, and location.
    """

    def __init__(
        self,
        name: str,
        byte_code: List["Instruction"],
        source_code: str,
        path: Path,
        location: Tuple[int, int],
        language: str = "python",
    ):
        self.name = name
        self.byte_code = byte_code
        self.source_code = source_code
        self.path = path
        self.location = location
        self.language = language
        self._embedding_count = None  # Cached embedding count

    def __repr__(self) -> str:
        return (
            f"CodeObject(name={self.name}, path={self.path}, location={self.location})"
        )

    def to_string(self, mapped: bool = True, one_line=True, for_hashing=False) -> str:
        instructions = []

        if Path(self.path).name in COMMON_TARGET_FILES.get(self.language, []):
            instructions += [SpecialCases.TARGETED_FILE.value]

        for instruction in self.byte_code:
            instructions.append(
                instruction.to_string(mapped=mapped, for_hashing=for_hashing)
            )

        return (" " if one_line else "\n").join(instructions)

    def to_hash(self) -> str:
        """
        Generate SHA256 hash of the oneline_mapped string representation.

        Returns:
            Hexadecimal SHA256 hash string
        """
        token_string = self.to_string(mapped=True, for_hashing=True, one_line=True)
        encoded_string = token_string.encode("utf-8", errors="replace")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(encoded_string)
        return sha256_hash.hexdigest()

    def get_tokens(self, mapped: bool = True) -> List[str]:
        """
        Get list of tokens from the bytecode instructions.

        Args:
            mapped: Whether to apply special token mapping

        Returns:
            List of token strings
        """
        tokens = []

        # Add file targeting warning if applicable
        if Path(self.path).name in COMMON_TARGET_FILES.get(self.language, []):
            tokens.append(SpecialCases.TARGETED_FILE.value)

        # Extract tokens from each instruction
        for instruction in self.byte_code:
            instruction_str = instruction.to_string(mapped=mapped, for_hashing=False)
            # Split instruction into opcode and argument tokens
            parts = instruction_str.split(" ", 1)
            tokens.append(
                parts[0].upper()
            )  # Convert opcode to uppercase to match tokenizer vocabulary
            if len(parts) > 1 and parts[1]:
                tokens.append(parts[1])

        return tokens

    @property
    def embedding_count(self) -> int:
        """
        Calculate the number of embeddings (tokens) this CodeObject would create
        when processed by the DistilBERT tokenizer.

        This helps identify when bytecode streams exceed DistilBERT's context window,
        which typically causes windowing and can affect model performance.

        Returns:
            Number of tokens this CodeObject creates when tokenized
        """
        if self._embedding_count is None:
            self._embedding_count = self._calculate_embedding_count()
        return self._embedding_count

    def _calculate_embedding_count(self) -> int:
        """
        Calculate embedding count by tokenizing the token string representation.

        Uses the same tokenization approach as DistilBERT prediction to ensure
        accurate token count estimation.

        Returns:
            Number of tokens produced by the tokenizer, or 0 if tokenizer not available
        """
        try:
            # Import here to avoid circular dependencies
            from common.predict_distilbert import get_thread_tokenizer

            # Get the token string (same format used for prediction)
            token_string = " ".join(self.get_tokens(mapped=True))

            # Use the same tokenizer that DistilBERT uses
            tokenizer = get_thread_tokenizer()

            # Tokenize without padding to get actual token count
            encoded = tokenizer(
                token_string,
                return_tensors="pt",
                padding=False,
                truncation=False,  # Don't truncate to see full size
            )

            # Return the number of tokens
            return encoded["input_ids"].shape[1]
        except (RuntimeError, ImportError, Exception):
            # Tokenizer not available or other error - return 0
            return 0

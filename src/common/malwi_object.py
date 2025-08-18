#!/usr/bin/env python


import yaml
import json

import hashlib


from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Optional, Any, Dict

from common.mapping import (
    SpecialCases,
    FUNCTION_MAPPING,
    IMPORT_MAPPING,
)
from common.bytecode import ASTCompiler
from common.predict_distilbert import (
    get_node_text_prediction,
)
from common.messaging import (
    file_error,
)

from common.files import read_json_from_file
from common.config import (
    EXTENSION_TO_LANGUAGE,
)


SCRIPT_DIR = Path(__file__).resolve().parent

SPECIAL_TOKENS: Dict[str, Dict] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "function_mapping.json"
)


def disassemble_file_ast(
    source_code: str,
    file_path: str,
    language: str,
    target_object_name: Optional[str] = None,
) -> List["MalwiObject"]:
    """
    Language-independent implementation using AST-to-malwicode API.
    Converts CodeObject instances from the AST compiler to MalwiObject instances.
    Supports both Python and JavaScript files.
    """
    all_objects: List[MalwiObject] = []
    current_file_errors: List[str] = []

    try:
        # Use the AST compiler with the detected language
        ast_compiler = ASTCompiler(language)
        code_objects = ast_compiler.process_file(Path(file_path))

        # Convert CodeObject instances to MalwiObject instances
        for code_obj in code_objects:
            # Handle target filtering if specified
            if target_object_name and code_obj.name != target_object_name:
                continue

            malwi_obj = MalwiObject(
                name=code_obj.name,
                language=language,
                file_path=file_path,
                file_source_code=source_code,
                # Store the AST CodeObject for token extraction
                ast_code_object=code_obj,
            )

            all_objects.append(malwi_obj)

        if target_object_name and all_objects:
            return [all_objects[0]]  # Return only the targeted object

    except UnicodeDecodeError:
        current_file_errors.append(SpecialCases.MALFORMED_FILE.value)
    except SyntaxError:
        current_file_errors.append(SpecialCases.MALFORMED_SYNTAX.value)
    except Exception:
        current_file_errors.append(SpecialCases.MALFORMED_FILE.value)

    # If compilation failed, create an error object
    if not all_objects and current_file_errors:
        all_objects.append(
            MalwiObject(
                name=SpecialCases.MALFORMED_FILE.value,
                language=language,
                file_path=file_path,
                file_source_code=source_code,
                warnings=current_file_errors,
            )
        )

    return all_objects


def process_single_file(
    file_path: Path,
    predict: bool = True,
    maliciousness_threshold: Optional[float] = None,
) -> Optional[Tuple[List["MalwiObject"], List["MalwiObject"]]]:
    try:
        source_code = file_path.read_text(encoding="utf-8", errors="replace")

        # Detect language based on file extension
        file_extension = file_path.suffix.lower()
        language = EXTENSION_TO_LANGUAGE.get(
            file_extension, "python"
        )  # Default to Python

        objects: List[MalwiObject] = disassemble_file_ast(
            source_code, file_path=str(file_path), language=language
        )

        all_objects = []
        malicious_objects = []

        for obj in objects:
            all_objects.append(obj)
            if predict:
                obj.predict()
                if (
                    maliciousness_threshold
                    and obj.maliciousness
                    and obj.maliciousness > maliciousness_threshold
                ):
                    malicious_objects.append(obj)

        return all_objects, malicious_objects

    except Exception as e:
        file_error(file_path, e, "processing")
        return [], []


class LiteralStr(str):
    pass


def literal_str_representer(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(LiteralStr, literal_str_representer)


@dataclass
class MalwiObject:
    name: str
    file_path: str
    warnings: List[str]
    file_source_code: str
    language: str
    code: Optional[str] = None
    maliciousness: Optional[float] = None
    ast_code_object: Optional[object] = (
        None  # Store AST CodeObject instead of Python CodeType
    )

    def __init__(
        self,
        name: str,
        language: str,
        file_path: str,
        file_source_code: str,
        ast_code_object: Optional[object] = None,
        warnings: List[str] = [],
    ):
        self.name = name
        self.language = language
        self.file_path = file_path
        self.warnings = list(warnings)
        self.maliciousness = None
        self.ast_code_object = ast_code_object
        self.file_source_code = file_source_code
        self.code = None

    @classmethod
    def all_tokens(cls, language: str = "python") -> List[str]:
        """Get all possible tokens for a language."""
        tokens = set()
        tokens.update([member.value for member in SpecialCases])
        tokens.update(FUNCTION_MAPPING.get(language, {}).values())
        tokens.update(IMPORT_MAPPING.get(language, {}).values())
        unique = list(tokens)
        unique.sort()
        return unique

    def to_tokens(self, map_special_tokens: bool = True) -> List[str]:
        """Extract tokens from the AST CodeObject."""
        all_token_parts: List[str] = []
        all_token_parts.extend(self.warnings)

        if self.ast_code_object:
            # Use AST CodeObject's get_tokens method with language-aware mapping
            ast_tokens = self.ast_code_object.get_tokens(mapped=map_special_tokens)
            all_token_parts.extend(ast_tokens)
        else:
            # Fallback for error cases
            all_token_parts.append(SpecialCases.MALFORMED_FILE.value)

        return all_token_parts

    def to_token_string(self, map_special_tokens: bool = True) -> str:
        return " ".join(self.to_tokens(map_special_tokens=map_special_tokens))

    def to_string_hash(self) -> str:
        tokens = self.to_token_string()
        encoded_string = tokens.encode("utf-8", errors="replace")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(encoded_string)
        return sha256_hash.hexdigest()

    def retrieve_source_code(self) -> Optional[str]:
        """Get source code from AST CodeObject."""
        if self.ast_code_object and hasattr(self.ast_code_object, "source_code"):
            self.code = self.ast_code_object.source_code
            return self.code
        elif self.ast_code_object:
            # Use the bytecode representation as fallback
            self.code = self.ast_code_object.to_string(mapped=False, one_line=False)
            return self.code
        return None

    @property
    def embedding_count(self) -> int:
        """
        Get the number of embeddings (tokens) this object would create when processed
        by the DistilBERT tokenizer.

        This helps identify when bytecode streams exceed DistilBERT's context window
        (typically 512 tokens), which causes windowing and can affect model performance.

        Returns:
            Number of tokens this object creates when tokenized for DistilBERT
        """
        if self.ast_code_object and hasattr(self.ast_code_object, "embedding_count"):
            return self.ast_code_object.embedding_count
        else:
            # No AST CodeObject available - cannot calculate embedding count
            return 0

    def predict(self) -> Optional[dict]:
        token_string = self.to_token_string()
        prediction = None
        if any(
            token in token_string
            for token in SPECIAL_TOKENS.get(self.language, {}).values()
        ):
            prediction = get_node_text_prediction(token_string)
        else:
            self.maliciousness = None
        if prediction and "probabilities" in prediction:
            self.maliciousness = prediction["probabilities"][1]
        return prediction

    def to_dict(self) -> dict:
        code_display_value = self.code
        if code_display_value is None:
            code_display_value = "<source not available>"

        # Normalize line endings for better YAML display
        if isinstance(code_display_value, str):
            # Convert \r\n and \r to \n for consistent line endings
            code_display_value = code_display_value.replace("\r\n", "\n").replace(
                "\r", "\n"
            )

            if "\n" in code_display_value:
                final_code_value = LiteralStr(code_display_value.strip())
            else:
                final_code_value = code_display_value
        else:
            final_code_value = code_display_value

        return {
            "path": str(self.file_path),
            "contents": [
                {
                    "name": self.name,
                    "score": self.maliciousness,
                    "code": final_code_value,
                    "tokens": self.to_token_string(),
                    "hash": self.to_string_hash(),
                    "embedding_count": self.embedding_count,
                }
            ],
        }

    def to_yaml(self) -> str:
        return yaml.dump(
            self.to_dict(),
            sort_keys=False,
            width=float("inf"),
            default_flow_style=False,
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=4)

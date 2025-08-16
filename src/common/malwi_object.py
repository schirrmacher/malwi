#!/usr/bin/env python

import sys
import yaml
import json
import time
import hashlib
from datetime import datetime

from tqdm import tqdm
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Any, Dict

from common.mapping import (
    SpecialCases,
    FUNCTION_MAPPING,
    IMPORT_MAPPING,
)
from common.bytecode import ASTCompiler
from common.predict_distilbert import (
    get_node_text_prediction,
    initialize_models as initialize_distilbert_models,
    get_model_version_string,
)
from common.messaging import (
    get_message_manager,
    file_error,
    path_error,
)
from malwi._version import __version__

from common.files import read_json_from_file
from common.config import (
    SUPPORTED_EXTENSIONS,
    EXTENSION_TO_LANGUAGE,
    EXTENSION_COMMENT_PREFIX,
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


@dataclass
class MalwiReport:
    """Result of processing files from a path."""

    all_objects: List["MalwiObject"]
    malicious_objects: List["MalwiObject"]
    threshold: float
    all_files: List[Path]
    skipped_files: List[Path]
    processed_files: int
    malicious: bool
    confidence: float
    activities: List[str]
    input: str  # The targeted folder/file path
    start: str  # ISO 8601 timestamp when scan started
    duration: float  # Duration in seconds
    version: str = field(
        default_factory=lambda: get_model_version_string(__version__)
    )  # Malwi version with model hash

    def _generate_report_data(self) -> Dict[str, Any]:
        processed_objects_count = len(self.all_objects)

        summary_statistics = {
            "total_files": len(self.all_files),
            "skipped_files": len(self.skipped_files),
            "processed_files": len(self.all_files) - len(self.skipped_files),
            "processed_objects": processed_objects_count,
            "malicious_objects": len(self.malicious_objects),
            "start": self.start,
            "duration": self.duration,
        }

        # Determine the result based on malicious flag and malicious objects count
        if self.malicious:
            result = "malicious"
        elif len(self.malicious_objects) > 0:
            result = "suspicious"
        else:
            result = "good"

        report_data = {
            "version": self.version,
            "input": self.input,
            "result": result,
            "statistics": summary_statistics,
            "details": [],
        }

        for obj in self.all_objects:
            is_malicious = (
                obj.maliciousness is not None and obj.maliciousness > self.threshold
            )

            if is_malicious:
                obj.retrieve_source_code()
                report_data["details"].append(obj.to_dict())

        return report_data

    def to_report_json(self) -> str:
        report_data = self._generate_report_data()
        return json.dumps(report_data, indent=4)

    def to_report_yaml(self) -> str:
        report_data = self._generate_report_data()
        return yaml.dump(
            report_data, sort_keys=False, width=float("inf"), default_flow_style=False
        )

    def to_demo_text(self) -> str:
        report_data = self._generate_report_data()
        stats = report_data["statistics"]
        result = report_data["result"]

        txt = f"- target: {report_data['input']}\n"
        txt += f"- seconds: {stats['duration']:.2f}\n"
        txt += f"- files: {stats['total_files']}\n"
        txt += f"  ├── scanned: {stats['processed_files']}\n"

        if result == "malicious" or result == "suspicious":
            txt += f"  ├── skipped: {stats['skipped_files']}\n"
            txt += "  └── suspicious:\n"

            # Group malicious objects by file path
            files_with_objects = {}
            for obj in self.malicious_objects:
                if obj.file_path not in files_with_objects:
                    files_with_objects[obj.file_path] = []
                files_with_objects[obj.file_path].append(obj)

            malicious_files = sorted(files_with_objects.keys())
            for i, file_path in enumerate(malicious_files):
                is_last_file = i == len(malicious_files) - 1
                if is_last_file:
                    txt += f"      └── {file_path}\n"
                    file_prefix = "          "
                else:
                    txt += f"      ├── {file_path}\n"
                    file_prefix = "      │   "

                # List objects in this file
                objects_in_file = files_with_objects[file_path]
                for j, obj in enumerate(objects_in_file):
                    is_last_object = j == len(objects_in_file) - 1
                    if is_last_object:
                        txt += f"{file_prefix}└── {obj.name}\n"
                        object_prefix = file_prefix + "    "
                    else:
                        txt += f"{file_prefix}├── {obj.name}\n"
                        object_prefix = file_prefix + "│   "

                    # List activities for this object
                    if result == "malicious":
                        # Get tokens for this specific object
                        obj_tokens = obj.to_tokens()
                        obj_activities = []
                        # Collect tokens from all languages represented in malicious objects
                        languages_in_objects = set(
                            o.language for o in self.malicious_objects
                        )
                        all_filter_values = set()
                        for lang in languages_in_objects:
                            all_filter_values.update(
                                FUNCTION_MAPPING.get(lang, {}).values()
                            )

                        obj_activities = list(
                            set(
                                [
                                    token
                                    for token in obj_tokens
                                    if token in all_filter_values
                                ]
                            )
                        )

                        for k, activity in enumerate(obj_activities):
                            is_last_activity = k == len(obj_activities) - 1
                            if is_last_activity:
                                txt += f"{object_prefix}└── {activity.lower().replace('_', ' ')}\n"
                            else:
                                txt += f"{object_prefix}├── {activity.lower().replace('_', ' ')}\n"
        else:
            txt += f"  └── skipped: {stats['skipped_files']}\n"

        txt += "\n"

        # Final result
        if result == "malicious":
            txt += f"=> 👹 malicious {self.confidence:.2f}\n"
        elif result == "suspicious":
            txt += f"=> ⚠️ suspicious {self.confidence:.2f}\n"
        else:  # result == "good"
            txt += "=> 🟢 good\n"

        return txt

    def to_report_markdown(
        self,
    ) -> str:
        report_data = self._generate_report_data()

        stats = report_data["statistics"]

        txt = "# Malwi Report\n\n"
        txt += f"*Generated by malwi v{self.version}*\n\n"
        txt += f"**Target:** `{report_data['input']}`\n\n"
        txt += "## Summary\n\n"
        txt += "Based on the analyzed patterns, the code is evaluated as:\n\n"

        # Use the same result classification
        result = report_data["result"]
        if result == "malicious":
            txt += f"> 👹 **Malicious**: `{self.confidence}`\n\n"
        elif result == "suspicious":
            txt += f"> ⚠️  **Suspicious**: `{self.confidence}`\n\n"
            txt += f"> *Found {stats['malicious_objects']} malicious objects but overall classification is not malicious*\n\n"
        else:  # good
            txt += f"> 🟢 **Good**: `{self.confidence}`\n\n"

        txt += f"- Files: {stats['total_files']}\n"
        txt += f"- Skipped: {stats['skipped_files']}\n"
        txt += f"- Processed Objects: {stats['processed_objects']}\n"
        txt += f"- Malicious Objects: {stats['malicious_objects']}\n\n"

        txt += "## Token Statistics\n\n"
        for activity in self.activities:
            txt += f"- {activity.lower().replace('_', ' ')}\n"
        txt += "\n"

        for file in report_data["details"]:
            txt += f"## {file['path']}\n\n"

            for object in file["contents"]:
                name = object["name"] if object["name"] else "<object>"
                score = object["score"]
                if score > self.threshold:
                    maliciousness = f"👹 `{round(score, 2)}`"
                else:
                    maliciousness = f"🟢 `{round(score, 2)}`"
                txt += f"- Object: `{name if name else 'Not defined'}`\n"
                txt += f"- Maliciousness: {maliciousness}\n\n"
                txt += "### Code\n\n"
                txt += f"```\n{object['code']}\n```\n\n"
                txt += "### Tokens\n\n"
                txt += f"```\n{object['tokens']}\n```\n"
            txt += "\n\n"

        return txt

    def to_tokens_text(self) -> str:
        """Generate tokens output format with visualization of malwicode -> DistilBERT token splitting."""
        lines = []

        # Group objects by file path to maintain organization
        files_with_objects = {}
        for obj in self.all_objects:
            if obj.file_path not in files_with_objects:
                files_with_objects[obj.file_path] = []
            files_with_objects[obj.file_path].append(obj)

        # Sort files for consistent output
        for file_path in sorted(files_with_objects.keys()):
            objects_in_file = files_with_objects[file_path]

            for obj in objects_in_file:
                # Add malwicode tokens
                malwicode_tokens = obj.to_tokens()
                token_string = obj.to_token_string()

                # Get DistilBERT tokens and counts
                try:
                    from common.predict_distilbert import get_thread_tokenizer

                    tokenizer = get_thread_tokenizer()
                    distilbert_tokens = tokenizer.tokenize(token_string)
                    distilbert_count = len(distilbert_tokens)
                    embedding_count = obj.embedding_count
                except Exception:
                    distilbert_tokens = None
                    distilbert_count = 0
                    embedding_count = obj.embedding_count

                # Add header with file path, object name, and counts
                lines.append("=" * 80)
                lines.append(f"📁 File: {file_path}")
                lines.append(f"🏷️  Object: {obj.name}")
                lines.append(
                    f"📊 Tokens: {len(malwicode_tokens)} malwicode → {distilbert_count} distilbert → {embedding_count} embeddings"
                )
                lines.append("=" * 80)
                lines.append("")

                # Add malwicode tokens
                lines.append("🔗 MALWICODE:")
                lines.append("─" * 40)

                # Format tokens in rows of 8 for better readability
                tokens_per_row = 8
                for i in range(0, len(malwicode_tokens), tokens_per_row):
                    row_tokens = malwicode_tokens[i : i + tokens_per_row]
                    lines.append("  " + " • ".join(row_tokens))

                lines.append("")

                # Add DistilBERT tokens if available
                if distilbert_tokens is not None:
                    lines.append("🤖 DISTILBERT:")
                    lines.append("─" * 40)

                    # Format DistilBERT tokens in rows of 10 for better readability
                    distilbert_per_row = 10
                    for i in range(0, len(distilbert_tokens), distilbert_per_row):
                        row_tokens = distilbert_tokens[i : i + distilbert_per_row]
                        lines.append("  " + " • ".join(row_tokens))

                else:
                    lines.append("🤖 DISTILBERT:")
                    lines.append("─" * 40)
                    lines.append("  (Tokenizer not available - models not initialized)")

                # Add extra spacing between objects
                lines.append("")
                lines.append("")

        # Remove trailing empty lines
        while lines and lines[-1] == "":
            lines.pop()

        return "\n".join(lines)

    def to_code_text(self) -> str:
        """Generate code output format: concatenated malicious code segments grouped by extension with path comments."""
        # Group malicious objects by file extension
        objects_by_extension = {}
        for obj in self.malicious_objects:
            # Get file extension
            file_path = Path(obj.file_path)
            extension = file_path.suffix.lower()

            if extension not in objects_by_extension:
                objects_by_extension[extension] = []
            objects_by_extension[extension].append(obj)

        # Build output for each extension group
        output_parts = []

        for extension in sorted(objects_by_extension.keys()):
            if not extension:  # Skip files without extension
                continue

            objects = objects_by_extension[extension]

            # Add header for this extension group
            output_parts.append(f"{'=' * 80}")
            output_parts.append(f"# Files with extension: {extension}")
            output_parts.append(f"{'=' * 80}")
            output_parts.append("")

            # Get comment style based on extension
            comment_prefix = EXTENSION_COMMENT_PREFIX.get(
                extension, "#"
            )  # Default to hash comments

            # Process each file's objects
            for obj in objects:
                # Retrieve source code if not already available
                if not obj.code:
                    obj.retrieve_source_code()

                if obj.code and obj.code != "<source not available>":
                    # Add file path comment with embedding count info
                    output_parts.append(f"{comment_prefix} {'=' * 70}")
                    output_parts.append(f"{comment_prefix} File: {obj.file_path}")
                    output_parts.append(f"{comment_prefix} Object: {obj.name}")
                    output_parts.append(
                        f"{comment_prefix} Embedding count: {obj.embedding_count} tokens"
                    )

                    # Add warning if it exceeds DistilBERT window
                    if obj.embedding_count > 512:
                        output_parts.append(
                            f"{comment_prefix} ⚠️  WOULD TRIGGER DISTILBERT WINDOWING (>{512} tokens)"
                        )

                    output_parts.append(f"{comment_prefix} {'=' * 70}")
                    output_parts.append("")

                    # Add the code
                    output_parts.append(obj.code)
                    output_parts.append("")
                    output_parts.append("")

        return "\n".join(output_parts)

    @classmethod
    def load_models_into_memory(
        cls,
        distilbert_model_path: Optional[str] = None,
        tokenizer_path: Optional[str] = None,
    ) -> None:
        """Load ML models into memory for batch processing."""
        MalwiObject.load_models_into_memory(
            distilbert_model_path=distilbert_model_path,
            tokenizer_path=tokenizer_path,
        )

    @classmethod
    def create(
        cls,
        input_path: Path,
        accepted_extensions: Optional[List[str]] = None,
        predict: bool = False,
        silent: bool = False,
        malicious_threshold: float = 0.7,
        on_malicious_found: Optional[callable] = None,
    ) -> "MalwiReport":
        """
        Create a MalwiReport by processing files from the given input path.

        Args:
            input_path: Path to file or directory to process
            accepted_extensions: List of file extensions to accept (without dots)
            predict: Whether to run maliciousness prediction
            silent: If True, suppress progress messages
            malicious_threshold: Threshold for classifying objects as malicious
            on_malicious_found: Optional callback function called when malicious objects are found
                               Function signature: callback(file_path: Path, malicious_objects: List[MalwiObject])

        Returns:
            MalwiReport containing analysis results
        """
        # Track timing and timestamp
        start_time = time.time()
        start_timestamp = datetime.now().isoformat()

        # Configure messaging to respect silent mode
        msg = get_message_manager()
        msg.set_quiet(silent)

        accepted_files, skipped_files = collect_files_by_extension(
            input_path=input_path,
            accepted_extensions=accepted_extensions,
            silent=silent,
        )

        all_files = accepted_files + skipped_files
        all_objects: List[MalwiObject] = []
        malicious_objects: List[MalwiObject] = []

        files_processed_count = 0

        if not accepted_files:
            duration = time.time() - start_time
            return cls(
                all_objects=[],
                malicious_objects=[],
                threshold=malicious_threshold,
                all_files=all_files,
                skipped_files=skipped_files,
                processed_files=files_processed_count,
                malicious=False,
                confidence=1.0,
                activities=[],
                input=str(input_path),
                start=start_timestamp,
                duration=duration,
            )

        # Configure progress bar
        tqdm_desc = (
            f"Analyzing '{input_path.name}'"
            if input_path.is_dir() and len(accepted_files) > 1
            else f"Processing '{input_path.name}'"
        )

        disable_tqdm = silent or (len(accepted_files) <= 1 and input_path.is_file())

        for file_path in tqdm(
            accepted_files,
            desc=tqdm_desc,
            unit="file",
            ncols=100,
            disable=disable_tqdm,
            leave=False,
            file=sys.stderr,  # Explicitly set stderr
            dynamic_ncols=True,  # Better terminal handling
            miniters=1,  # Force updates
            mininterval=0.1,  # Minimum update interval
        ):
            try:
                file_all_objects, file_malicious_objects = process_single_file(
                    file_path,
                    predict=predict,
                    maliciousness_threshold=malicious_threshold,
                )
                all_objects.extend(file_all_objects)
                malicious_objects.extend(file_malicious_objects)
                files_processed_count += 1

                # Call callback if malicious objects found and callback provided
                if file_malicious_objects and on_malicious_found:
                    on_malicious_found(file_path, file_malicious_objects)

            except Exception as e:
                if not silent:
                    file_error(file_path, e, "critical processing")

        # Determine maliciousness based on DistilBERT predictions only
        malicious = len(malicious_objects) > 0

        # Calculate confidence based on average maliciousness score of detected objects
        if malicious_objects:
            confidence = sum(
                obj.maliciousness for obj in malicious_objects if obj.maliciousness
            ) / len(malicious_objects)
        else:
            confidence = 1.0  # High confidence for clean files

        # Generate activity list from malicious objects for reporting
        activities = []
        if malicious_objects:
            # Extract function tokens from malicious objects for activity reporting
            function_tokens = set()
            # Collect tokens from all languages represented in malicious objects
            languages_in_objects = set(obj.language for obj in malicious_objects)
            all_filter_values = set()
            for lang in languages_in_objects:
                all_filter_values.update(FUNCTION_MAPPING.get(lang, {}).values())

            for obj in malicious_objects:
                tokens = obj.to_tokens()
                function_tokens.update(
                    token for token in tokens if token in all_filter_values
                )
            activities = list(function_tokens)

        duration = time.time() - start_time
        return cls(
            all_objects=all_objects,
            malicious_objects=malicious_objects,
            threshold=malicious_threshold,
            all_files=all_files,
            skipped_files=skipped_files,
            processed_files=files_processed_count,
            malicious=malicious,
            confidence=confidence,
            activities=activities,
            input=str(input_path),
            start=start_timestamp,
            duration=duration,
        )


def collect_files_by_extension(
    input_path: Path,
    accepted_extensions: Optional[List[str]] = None,
    silent: bool = False,
) -> Tuple[List[Path], List[Path]]:
    """
    Collect files from the input path, filtering by accepted extensions.

    Args:
        input_path: Path to file or directory
        accepted_extensions: List of file extensions to accept (without dots)
        silent: If True, suppress error messages

    Returns:
        Tuple of (accepted_files, skipped_files)
    """
    if accepted_extensions is None:
        accepted_extensions = SUPPORTED_EXTENSIONS

    normalized_extensions = [ext.lower().lstrip(".") for ext in accepted_extensions]
    accepted_files = []
    skipped_files = []

    if not input_path.exists():
        if not silent:
            path_error(input_path)
        return accepted_files, skipped_files

    if input_path.is_file():
        file_extension = input_path.suffix.lstrip(".").lower()
        if file_extension in normalized_extensions:
            accepted_files.append(input_path)
        else:
            skipped_files.append(input_path)

    elif input_path.is_dir():
        for file_path in input_path.rglob("*"):
            if file_path.is_file():
                file_extension = file_path.suffix.lstrip(".").lower()
                if file_extension in normalized_extensions:
                    accepted_files.append(file_path)
                else:
                    skipped_files.append(file_path)

    else:
        skipped_files.append(input_path)

    return accepted_files, skipped_files


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
    def load_models_into_memory(
        cls,
        distilbert_model_path: Optional[str] = None,
        tokenizer_path: Optional[str] = None,
    ) -> None:
        initialize_distilbert_models(
            model_path=distilbert_model_path, tokenizer_path=tokenizer_path
        )

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

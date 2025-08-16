#!/usr/bin/env python

import sys
import yaml
import json
import time
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict

from tqdm import tqdm

from common.mapping import FUNCTION_MAPPING
from common.predict_distilbert import get_model_version_string
from common.messaging import get_message_manager, file_error
from common.files import collect_files_by_extension
from common.config import EXTENSION_COMMENT_PREFIX
from common.malwi_object import MalwiObject
from malwi._version import __version__


@dataclass
class MalwiReport:
    """Result of processing files from a path."""

    all_objects: List[MalwiObject]
    malicious_objects: List[MalwiObject]
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
    all_file_types: List[str]  # All file extensions found in the scanned package
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
            "file_types": self.all_file_types,
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

        # Calculate file types for processed and skipped files
        processed_files = [f for f in self.all_files if f not in self.skipped_files]
        processed_types = list(
            set(f.suffix.lower() for f in processed_files if f.suffix)
        )
        skipped_types = list(
            set(f.suffix.lower() for f in self.skipped_files if f.suffix)
        )
        processed_types.sort()
        skipped_types.sort()

        # Format file type strings
        processed_types_str = (
            f" ({', '.join(processed_types)})" if processed_types else ""
        )
        skipped_types_str = f" ({', '.join(skipped_types)})" if skipped_types else ""

        txt = f"- target: {report_data['input']}\n"
        txt += f"- seconds: {stats['duration']:.2f}\n"
        txt += f"- files: {stats['total_files']}\n"
        txt += f"  ├── scanned: {stats['processed_files']}{processed_types_str}\n"

        if result == "malicious" or result == "suspicious":
            txt += f"  ├── skipped: {stats['skipped_files']}{skipped_types_str}\n"
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
            txt += f"  └── skipped: {stats['skipped_files']}{skipped_types_str}\n"

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

        # Group malicious objects by file path to maintain organization
        files_with_objects = {}
        for obj in self.malicious_objects:  # Only show malicious objects
            if obj.file_path not in files_with_objects:
                files_with_objects[obj.file_path] = []
            files_with_objects[obj.file_path].append(obj)

        # Handle case when no malicious objects found
        if not files_with_objects:
            lines.append("=" * 80)
            lines.append("📊 TOKENS OUTPUT")
            lines.append("=" * 80)
            lines.append("")
            lines.append("✅ No malicious objects found - nothing to display")
            lines.append("")
            return "\n".join(lines)

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

                # Add object name with location info if available
                object_line = f"🏷️  Object: {obj.name}"
                if hasattr(obj, "ast_code_object") and obj.ast_code_object:
                    if hasattr(obj.ast_code_object, "location"):
                        start_line, end_line = obj.ast_code_object.location
                        object_line += f" 📍 Lines {start_line}-{end_line}"
                lines.append(object_line)

                lines.append(
                    f"📊 Tokens: {len(malwicode_tokens)} malwicode → {distilbert_count} distilbert → {embedding_count} embeddings"
                )
                if obj.maliciousness is not None:
                    lines.append(f"🎯 Maliciousness: {obj.maliciousness:.4f}")
                lines.append("=" * 80)
                lines.append("")

                # Add source code - handle module objects differently
                lines.append("📝 SOURCE CODE:")
                lines.append("─" * 40)

                # For module objects, show the module-level source code
                if obj.name == "<module>":
                    # Get module-level source code from CodeObject
                    source_to_display = None
                    if hasattr(obj, "ast_code_object") and obj.ast_code_object:
                        if hasattr(obj.ast_code_object, "source_code"):
                            source_to_display = obj.ast_code_object.source_code

                    if source_to_display and source_to_display.strip():
                        # Add line numbers to source code for better readability
                        source_lines = source_to_display.split("\n")
                        for i, line in enumerate(source_lines, 1):
                            if line.strip():  # Only show non-empty lines
                                lines.append(f"  {i:4d} | {line}")
                    else:
                        lines.append(
                            "  [No module-level code - file contains only function/class definitions]"
                        )
                else:
                    # For functions and classes, show their specific source code
                    source_to_display = None
                    if hasattr(obj, "ast_code_object") and obj.ast_code_object:
                        if hasattr(obj.ast_code_object, "source_code"):
                            source_to_display = obj.ast_code_object.source_code

                    # Fallback to file source code if CodeObject source not available
                    if source_to_display is None and hasattr(obj, "file_source_code"):
                        source_to_display = obj.file_source_code

                    if source_to_display:
                        # Add line numbers to source code for better readability
                        source_lines = source_to_display.split("\n")
                        # Get starting line number if we have location info
                        start_line_num = 1
                        if hasattr(obj, "ast_code_object") and obj.ast_code_object:
                            if hasattr(obj.ast_code_object, "location"):
                                start_line_num = obj.ast_code_object.location[0]

                        for i, line in enumerate(source_lines, start_line_num):
                            lines.append(f"  {i:4d} | {line}")
                    else:
                        lines.append("  [Source code not available]")
                lines.append("")

                # Add DistilBERT tokens if available
                if distilbert_tokens is not None:
                    lines.append("🔗 TOKENS:")
                    lines.append("─" * 40)

                    # Format DistilBERT tokens in rows of 10 for better readability
                    distilbert_per_row = 10
                    for i in range(0, len(distilbert_tokens), distilbert_per_row):
                        row_tokens = distilbert_tokens[i : i + distilbert_per_row]
                        lines.append("  " + " • ".join(row_tokens))

                else:
                    lines.append("🔗 TOKENS:")
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
        from common.malwi_object import MalwiObject

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
        # Import here to avoid circular imports
        from common.malwi_object import process_single_file

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

        # Extract all unique file extensions found in the package
        all_file_types = list(
            set(
                file_path.suffix.lower()
                for file_path in all_files
                if file_path.suffix  # Only include files with extensions
            )
        )
        all_file_types.sort()  # Sort for consistent ordering

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
                all_file_types=all_file_types,
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
            all_file_types=all_file_types,
        )

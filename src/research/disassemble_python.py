#!/usr/bin/env python

import os
import sys
import csv
import yaml
import json
import types
import base64
import inspect
import pathlib
import hashlib
import warnings
import argparse
import questionary

from tqdm import tqdm
from enum import Enum
from pathlib import Path
from collections import Counter
from dataclasses import dataclass
from ollama import ChatResponse, chat
from typing import List, Tuple, Set, TextIO, Optional, Any, Dict, Union

from research.mapping import (
    SpecialCases,
    tokenize_code_type,
    COMMON_TARGET_FILES,
    FUNCTION_MAPPING,
    IMPORT_MAPPING,
)
from research.predict_distilbert import (
    get_node_text_prediction,
    initialize_models as initialize_distilbert_models,
)
from research.predict_svm_layer import initialize_svm_model, predict as svm_predict
from common.messaging import (
    get_message_manager,
    file_error,
    path_error,
    model_warning,
    info,
    progress,
    error,
    success,
    warning,
    debug,
    critical,
)
from malwi._version import __version__

from common.files import read_json_from_file

CONFIDENCE_MALICIOUSNESS_THRESHOLD = 0.8

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent

SPECIAL_TOKENS: Set[str] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "function_mapping.json"
)


class MetaAttributes(Enum):
    # Additional attributes for SVM layer training
    MALICIOUS_COUNT = "MALICIOUS_COUNT"


class CSVWriter:
    """Handles CSV output operations."""

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
            self.writer.writerow(["tokens", "hash", "filepath"])

    def write_objects(self, objects_data: List["MalwiObject"]) -> None:
        """Write MalwiObject data to CSV."""
        for obj in objects_data:
            self.writer.writerow(
                [
                    obj.to_token_string(),
                    obj.to_string_hash(),
                    obj.file_path,
                ]
            )

    def close(self):
        """Close the CSV file."""
        if self.file_handle:
            self.file_handle.close()


def recursively_disassemble_python(
    file_path: str,
    source_code: str,
    language: str,
    code_obj: Optional[types.CodeType],
    all_objects_data: List["MalwiObject"],
    visited_code_ids: Optional[Set[int]] = None,
    errors: Optional[List[str]] = None,
) -> None:
    current_errors = list(errors) if errors is not None else []

    if current_errors or not code_obj:
        for err_msg in current_errors:
            object_data = MalwiObject(
                name=err_msg,
                language=language,
                file_path=file_path,
                code_type=None,
                file_source_code="",
                warnings=[err_msg],
            )
            all_objects_data.append(object_data)
        if not code_obj and not current_errors:
            all_objects_data.append(
                MalwiObject(
                    name=SpecialCases.MALFORMED_FILE.value,
                    language=language,
                    file_path=file_path,
                    file_source_code="",
                    warnings=[SpecialCases.MALFORMED_FILE.value],
                )
            )
        return

    if visited_code_ids is None:
        visited_code_ids = set()

    if id(code_obj) in visited_code_ids:
        return
    visited_code_ids.add(id(code_obj))

    object_data = MalwiObject(
        name=code_obj.co_qualname,
        language=language,
        file_path=file_path,
        code_type=code_obj,
        file_source_code=source_code,
    )
    all_objects_data.append(object_data)

    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            recursively_disassemble_python(
                file_path=file_path,
                source_code=source_code,
                language=language,
                code_obj=const,
                all_objects_data=all_objects_data,
                visited_code_ids=visited_code_ids,
            )


def find_code_object_by_name(
    code: types.CodeType, target_name: str
) -> Optional[types.CodeType]:
    if code.co_qualname == target_name:
        return code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            result = find_code_object_by_name(const, target_name)
            if result:
                return result
    return None


def disassemble_python_file(
    source_code: str, file_path: str, target_object_name: Optional[str] = None
) -> List["MalwiObject"]:
    all_objects: List[MalwiObject] = []
    current_file_errors: List[str] = []

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            code_object = compile(source_code, file_path, "exec")

        if target_object_name:
            target_code = find_code_object_by_name(code_object, target_object_name)
            if target_code:
                return [
                    MalwiObject(
                        name=target_code.co_qualname,
                        language="python",
                        file_path=file_path,
                        file_source_code=source_code,
                        code_type=target_code,
                    )
                ]

    except UnicodeDecodeError:
        current_file_errors.append(SpecialCases.MALFORMED_FILE.value)
        code_object = None
    except SyntaxError:
        current_file_errors.append(SpecialCases.MALFORMED_SYNTAX.value)
        code_object = None
    except Exception:
        current_file_errors.append(SpecialCases.MALFORMED_FILE.value)
        code_object = None

    # If compilation failed and no errors were caught, add fallback error
    if code_object is None and not current_file_errors:
        current_file_errors.append(SpecialCases.FILE_READING_ISSUES.value)

    recursively_disassemble_python(
        file_path=file_path,
        source_code=source_code,
        language="python",
        code_obj=code_object,
        all_objects_data=all_objects,
        errors=current_file_errors,
    )

    return all_objects


def process_single_file(
    file_path: Path,
    predict: bool = True,
    retrieve_source_code: bool = True,
    maliciousness_threshold: Optional[float] = None,
) -> Optional[Tuple[List["MalwiObject"], List["MalwiObject"]]]:
    try:
        source_code = file_path.read_text(encoding="utf-8", errors="replace")
        objects: List[MalwiObject] = disassemble_python_file(
            source_code, file_path=str(file_path)
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

            if retrieve_source_code:
                obj.retrieve_source_code()

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
    version: str = __version__  # Malwi version used for this report

    def _generate_report_data(
        self,
        include_source_files: bool = True,
    ) -> Dict[str, Any]:
        processed_objects_count = len(self.all_objects)

        summary_statistics = {
            "total_files": len(self.all_files),
            "skipped_files": len(self.skipped_files),
            "processed_files": len(self.all_files) - len(self.skipped_files),
            "processed_objects": processed_objects_count,
            "malicious_objects": len(self.malicious_objects),
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
            "result": result,
            "statistics": summary_statistics,
            "details": [],
        }

        if include_source_files:
            report_data["sources"] = {}

        for obj in self.all_objects:
            is_malicious = (
                obj.maliciousness is not None and obj.maliciousness > self.threshold
            )

            if is_malicious:
                obj.retrieve_source_code()
                report_data["details"].append(obj.to_dict())

                if include_source_files:
                    report_data["sources"][obj.file_path] = base64.b64encode(
                        obj.file_source_code.encode("utf-8", errors="replace")
                    ).decode("utf-8")

        return report_data

    def to_report_csv(self, output_stream: TextIO) -> None:
        """Format objects as CSV and write to a stream."""
        writer = csv.writer(output_stream)
        writer.writerow(["tokens", "hash", "filepath"])
        for obj in self.all_objects:
            writer.writerow(
                [
                    obj.to_token_string(),
                    obj.to_string_hash(),
                    obj.file_path,
                ]
            )

    def to_report_json(
        self,
        include_source_files: bool = True,
    ) -> str:
        report_data = self._generate_report_data(
            include_source_files=include_source_files,
        )
        return json.dumps(report_data, indent=4)

    def to_report_yaml(
        self,
        include_source_files: bool = True,
    ) -> str:
        report_data = self._generate_report_data(
            include_source_files=include_source_files,
        )
        return yaml.dump(
            report_data, sort_keys=False, width=float("inf"), default_flow_style=False
        )

    def to_demo_text(self) -> str:
        report_data = self._generate_report_data(include_source_files=True)
        stats = report_data["statistics"]
        result = report_data["result"]

        txt = f"- files: {stats['total_files']}\n"
        txt += f"  ├── scanned: {stats['processed_files']}\n"
        txt += f"  └── skipped: {stats['skipped_files']}\n"
        txt += f"- objects: {stats['processed_objects']}\n"

        # Use the same three-state result system as other report formats
        if result == "malicious":
            txt += f"  └── malicious: {stats['malicious_objects']} \n"
            activity_list = list(self.activities)
            for i, activity in enumerate(activity_list):
                if i == len(list(activity_list)) - 1:
                    txt += f"      └── {activity.lower().replace('_', ' ')}\n"
                else:
                    txt += f"      ├── {activity.lower().replace('_', ' ')}\n"
            txt += "\n"
            txt += f"=> 👹 malicious {self.confidence:.2f}\n"
        elif result == "suspicious":
            txt += f"  └── suspicious: {stats['malicious_objects']}\n\n"
            txt += f"=> ⚠️ suspicious {self.confidence:.2f}\n"
        else:  # result == "good"
            txt += "\n"
            txt += "=> 🟢 good\n"

        return txt

    def to_report_markdown(
        self,
    ) -> str:
        report_data = self._generate_report_data(include_source_files=True)

        stats = report_data["statistics"]

        txt = "# Malwi Report\n\n"
        txt += f"*Generated by malwi v{self.version}*\n\n"
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
        accepted_extensions = ["py"]

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


def process_files(
    input_path: Path,
    accepted_extensions: Optional[List[str]] = None,
    predict: bool = False,
    retrieve_source_code: bool = False,
    silent: bool = False,
    triaging_type: Optional[str] = None,
    malicious_threshold: float = 0.7,
    predict_svm: bool = True,
    llm_api_key: Optional[str] = None,
) -> MalwiReport:
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
        return MalwiReport(
            all_objects=[],
            malicious_objects=[],
            threshold=malicious_threshold,
            all_files=all_files,
            skipped_files=skipped_files,
            processed_files=files_processed_count,
            malicious=False,
            confidence=1.0,
            activities=[],
        )

    # Configure progress bar
    tqdm_desc = (
        f"Processing directory '{input_path.name}'"
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
                retrieve_source_code=retrieve_source_code,
                maliciousness_threshold=malicious_threshold,
            )
            all_objects.extend(file_all_objects)
            malicious_objects.extend(file_malicious_objects)
            files_processed_count += 1

            if triaging_type:
                triage(
                    file_all_objects,
                    out_path="triaging",
                    malicious_threshold=malicious_threshold,
                    triaging_type=triaging_type,
                    llm_api_key=llm_api_key,
                )

        except Exception as e:
            if not silent:
                file_error(file_path, e, "critical processing")

    if len(malicious_objects) == 0:
        return MalwiReport(
            all_objects=all_objects,
            malicious_objects=[],
            threshold=malicious_threshold,
            all_files=all_files,
            skipped_files=skipped_files,
            processed_files=files_processed_count,
            malicious=False,
            confidence=1.0,
            activities=[],
        )

    if not predict_svm:
        return MalwiReport(
            all_objects=all_objects,
            malicious_objects=malicious_objects,
            threshold=malicious_threshold,
            all_files=all_files,
            skipped_files=skipped_files,
            processed_files=files_processed_count,
            malicious=False,
            confidence=0.0,
            activities=[],
        )

    token_stats = MalwiObject.collect_token_stats(
        malicious_objects,
        file_count=len(all_files),
        malicious_count=len(malicious_objects),
    )

    # Filter for functions only since those are mainly interesting when investigating
    filter_values = set(FUNCTION_MAPPING.get("python", {}).values())
    top_activities = sorted(
        ((k, v) for k, v in token_stats.items() if v > 0 and k in filter_values),
        key=lambda item: item[1],
        reverse=True,
    )
    top_activities_string = (f"{k}: {v}" for k, v in top_activities)

    prediction = svm_predict(token_stats)

    malicious = prediction["malicious"]
    confidence = (
        prediction["confidence_malicious"]
        if malicious
        else prediction["confidence_benign"]
    )

    if not malicious and confidence < CONFIDENCE_MALICIOUSNESS_THRESHOLD:
        malicious = True
        confidence = prediction["confidence_malicious"]

    return MalwiReport(
        all_objects=all_objects,
        malicious_objects=malicious_objects,
        threshold=malicious_threshold,
        all_files=all_files,
        skipped_files=skipped_files,
        processed_files=files_processed_count,
        malicious=malicious,
        confidence=confidence,
        activities=top_activities_string,
    )


def save_yaml_report(obj: "MalwiObject", path: str, code_hash: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                MalwiObject.to_report_yaml(
                    [obj],
                    [obj.file_path],
                    malicious_threshold=0.0,
                    number_of_skipped_files=0.0,
                )
            )
        success(f"Saved data for hash {code_hash} to {path}")
    except IOError as e:
        error(f"Failed to write YAML file {path}: {e}")
    except Exception as e:
        error(f"Failed to save YAML data for hash {code_hash}: {e}")


def manual_triage(
    obj: "MalwiObject", code_hash: str, benign_path: str, malicious_path: str
) -> None:
    triage_result: Optional[str] = questionary.select(
        f"Is the following code malicious?\n\n# Original Maliciousness: {obj.maliciousness}\n# {obj.file_path}\n\n{obj.code}\n\n{obj.to_token_string()}",
        use_shortcuts=True,
        multiline=True,
        choices=["yes", "no", "tokens", "skip", "exit"],
    ).ask()

    if triage_result == "yes":
        obj.maliciousness = 1.0
        save_yaml_report(obj, malicious_path, code_hash)
    elif triage_result == "no":
        obj.maliciousness = 0.0
        save_yaml_report(obj, benign_path, code_hash)
    elif triage_result == "skip":
        info(f"Skipping sample {code_hash}...")
    elif triage_result == "exit" or triage_result is None:
        info("Exiting triage process.")
        exit(0)
    elif triage_result == "tokens" or triage_result is None:
        triage_result: Optional[str] = questionary.select(
            obj.to_token_string(),
            choices=["proceed", "exit"],
        ).ask()
        if triage_result == "proceed" or triage_result is None:
            manual_triage(
                obj=obj,
                code_hash=code_hash,
                benign_path=benign_path,
                malicious_path=malicious_path,
            )
        elif triage_result == "exit":
            info("Exiting triage process.")
            exit(0)
    else:
        warning(f"Unknown triage result '{triage_result}', skipping sample {code_hash}")


def auto_triage(
    obj: "MalwiObject",
    code_hash: str,
    path: str,
) -> None:
    save_yaml_report(obj, path, code_hash)


def ollama_triage(
    obj: "MalwiObject",
    code_hash: str,
    benign_path: str,
    malicious_path: str,
    prompt: str,
    model: str = "gemma3",
) -> None:
    try:
        response: ChatResponse = chat(
            model=model,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
        )

        result_text = response.message.content

        if "yes" in result_text:
            obj.maliciousness = 1.0
            save_yaml_report(obj, malicious_path, code_hash)
            success("Code categorized as malicious")
        elif "no" in result_text:
            obj.maliciousness = 0.0
            save_yaml_report(obj, benign_path, code_hash)
            success("Code categorized as benign")
        else:
            warning(f"Unclear LLM response for {code_hash}: {result_text}, skipping")

    except Exception as e:
        error_message = str(e)
        error(f"Failed to authenticate with LLM service: {error_message}")
        sys.exit(1)


def triage(
    all_objects: List["MalwiObject"],
    out_path: Path,
    malicious_threshold: float = 0.7,
    grep_string: str = None,
    max_tokens: int = 0,
    triaging_type: str = "manual",
    auto_triaging: Optional[str] = None,
    llm_api_key: Optional[str] = None,
    llm_prompt: Optional[str] = None,
    llm_model: str = "gemma3",
):
    benign_dir = os.path.join(out_path, "benign")
    malicious_dir = os.path.join(out_path, "malicious")

    os.makedirs(benign_dir, exist_ok=True)
    os.makedirs(malicious_dir, exist_ok=True)

    for obj in all_objects:
        if obj.maliciousness < malicious_threshold:
            continue

        obj.retrieve_source_code()

        if not hasattr(obj, "code") or not obj.code:
            debug("Object has no source code, skipping...")
            continue

        if grep_string and not (grep_string in obj.name or grep_string in obj.code):
            continue

        if max_tokens > 0 and len(obj.to_tokens()) >= max_tokens:
            continue

        code_hash = hashlib.sha1(obj.code.encode("utf-8", errors="replace")).hexdigest()

        benign_path = os.path.join(benign_dir, f"{code_hash}.yaml")
        malicious_path = os.path.join(malicious_dir, f"{code_hash}.yaml")

        if os.path.exists(benign_path) or os.path.exists(malicious_path):
            debug(f"Hash {code_hash} already exists, skipping...")
            continue

        prompt = llm_prompt
        if not prompt:
            prompt = f"""You are a professional security code reviewer.
Please analyze the following code sample and determine whether it exhibits any signs of malicious behavior.
Examples of malicious behavior include (but are not limited to):
- Data exfiltration attempts
- Code obfuscation or dynamic code execution (e.g., eval, exec, reflection)
- Unauthorized access or privilege escalation
- Suspicious network, file system, or subprocess activity
- Malicious or hidden behavior during installation or setup
- Modification of system files, environment variables, or dependencies
- Installation of unnecessary or unverified packages, especially from untrusted sources
- Use or misuse of cryptographic functions (e.g., weak algorithms, hardcoded secrets)
- Hardcoded, exposed, or improperly handled cryptographic key material or credentials
Answer 'yes' or 'no'.\n\n```{obj.code}\n```"""
        else:
            prompt = f"{prompt}\n\n```{obj.code}\n```"

        if triaging_type == "ollama":
            ollama_triage(
                obj=obj,
                code_hash=code_hash,
                benign_path=benign_path,
                malicious_path=malicious_path,
                prompt=prompt,
                model=llm_model,
            )
        elif triaging_type == "auto":
            auto_triage(
                obj,
                code_hash,
                benign_path if auto_triaging == "benign" else malicious_path,
            )
        else:
            manual_triage(obj, code_hash, benign_path, malicious_path)


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
    code: Optional[str] = None
    maliciousness: Optional[float] = None
    code_type: Optional[types.CodeType] = None

    def __init__(
        self,
        name: str,
        language: str,
        file_path: str,
        file_source_code: str,
        code_type: types.CodeType = None,
        warnings: List[str] = [],
    ):
        self.name = name
        self.file_path = file_path
        self.warnings = list(warnings)
        self.maliciousness = None
        self.code_type = code_type
        self.file_source_code = file_source_code

        if Path(self.file_path).name in COMMON_TARGET_FILES.get(language, []):
            self.warnings += [SpecialCases.TARGETED_FILE.value]

    @classmethod
    def collect_token_stats(
        cls,
        objects: List["MalwiObject"],
        file_count: int = 0,
        malicious_count: int = 0,
    ) -> dict[str, int]:
        result: Counter = Counter()

        for obj in objects:
            stats = obj.calculate_token_stats()
            result.update(stats)

        # 1. Ensure all possible tokens are present in the result, initializing to 0 if not observed.
        # This resolves the "empty string" issue by guaranteeing a 0 for unobserved features.
        for token in cls.all_tokens():
            if token not in result:
                result[token] = 0

        # 2. Explicitly set MetaAttributes that are passed as arguments or calculated.
        # This fixes the FILE_COUNT bug.
        result[MetaAttributes.MALICIOUS_COUNT.value] = malicious_count

        return dict(result)

    @classmethod
    def create_decision_tokens(
        cls,
        objects: List["MalwiObject"],
        file_count: int = 0,
        malicious_count: int = 0,
    ) -> str:
        """
        Create a string of tokens ordered by their count (high to low) for tokens with non-zero values.

        Args:
            objects: List of MalwiObject instances to analyze
            file_count: Number of files processed
            malicious_count: Number of malicious objects found

        Returns:
            A space-separated string of tokens ordered by their count
        """
        # Get token statistics
        token_stats = cls.collect_token_stats(objects, file_count, malicious_count)

        # Filter tokens with value greater than zero and sort by count (high to low)
        non_zero_tokens = [
            (token, count) for token, count in token_stats.items() if count > 0
        ]
        sorted_tokens = sorted(non_zero_tokens, key=lambda x: x[1], reverse=True)

        # Create string from ordered tokens
        ordered_tokens = [token for token, count in sorted_tokens]
        return " ".join(ordered_tokens)

    @classmethod
    def load_models_into_memory(
        cls,
        distilbert_model_path: Optional[str] = None,
        tokenizer_path: Optional[str] = None,
        svm_layer_path: Optional[str] = None,
    ) -> None:
        initialize_distilbert_models(
            model_path=distilbert_model_path, tokenizer_path=tokenizer_path
        )
        initialize_svm_model(svm_layer_path)

    @classmethod
    def all_tokens(
        cls,
    ) -> None:
        tokens = set()
        tokens.update([member.value for member in SpecialCases])
        tokens.update([member.value for member in MetaAttributes])
        tokens.update(FUNCTION_MAPPING.get("python", {}).values())
        tokens.update(IMPORT_MAPPING.get("python", {}).values())
        unique = list(tokens)
        unique.sort()
        return unique

    def to_tokens(self, map_special_tokens: bool = True) -> List[str]:
        all_token_parts: List[str] = []
        all_token_parts.extend(self.warnings)
        generated_instructions = tokenize_code_type(
            code_type=self.code_type, map_special_tokens=map_special_tokens
        )
        all_token_parts.extend(generated_instructions)
        return all_token_parts

    def calculate_token_stats(self) -> dict:
        token_counts = Counter(self.to_tokens())
        stats = {token: token_counts.get(token, 0) for token in self.all_tokens()}
        return stats

    def to_token_string(self, map_special_tokens: bool = True) -> str:
        return " ".join(self.to_tokens(map_special_tokens=map_special_tokens))

    def to_string_hash(self) -> str:
        tokens = self.to_token_string()
        encoded_string = tokens.encode("utf-8", errors="replace")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(encoded_string)
        return sha256_hash.hexdigest()

    def retrieve_source_code(self) -> Optional[str]:
        try:
            self.code = inspect.getsource(self.code_type)
            return self.code
        except Exception:
            pass
        return None

    def predict(self) -> Optional[dict]:
        token_string = self.to_token_string()
        prediction = None
        if any(
            token in token_string for token in SPECIAL_TOKENS.get("python", {}).values()
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

        if isinstance(code_display_value, str) and "\n" in code_display_value:
            final_code_value = LiteralStr(code_display_value.strip())
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

    @classmethod
    def from_file(
        cls, file_path: Union[str, Path], language: str = "python"
    ) -> List["MalwiObject"]:
        file_path = Path(file_path)
        malwi_objects: List[MalwiObject] = []

        with file_path.open("r", encoding="utf-8") as f:
            if file_path.suffix in [".yaml", ".yml"]:
                # Load all YAML documents in the file
                documents = yaml.safe_load_all(f)
            elif file_path.suffix == ".json":
                # JSON normally single doc; for multiple JSON objects in one file,
                # you could do more advanced parsing, but here just one load:
                documents = [json.load(f)]
            else:
                raise ValueError(f"Unsupported file type: {file_path.suffix}")

            for data in documents:
                if not data:
                    continue
                details = data.get("details", [])
                for detail in details:
                    if not details:
                        continue
                    file_path = detail.get("path", "") or ""
                    raw_source = data.get("sources", {}).get(file_path)
                    source = base64.b64decode(raw_source).decode("utf-8")
                    contents = detail.get("contents", [])

                    if not contents:
                        continue
                    for item in contents:
                        name = item.get("name")
                        file_path_val = file_path
                        warnings = item.get("warnings", [])

                        matchingCodeType = disassemble_python_file(
                            source_code=source,
                            file_path=file_path,
                            target_object_name=name,
                        )

                        malwi_object = cls(
                            name=name,
                            file_source_code=source,
                            language=language,
                            file_path=file_path_val,
                            warnings=warnings,
                            code_type=matchingCodeType[0].code_type,
                        )
                        malwi_objects.append(malwi_object)

        return malwi_objects


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Recursively disassemble Python files",
        epilog="Example: python %(prog)s your_script.or_directory --format txt --save output.txt",
    )
    parser.add_argument(
        "path", metavar="PATH", help="The Python file or directory to process."
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        choices=["txt", "csv", "json", "yaml"],
        default="txt",
        help="Output format (default: txt). 'json' and 'yaml' are report formats.",
    )
    parser.add_argument(
        "-s",
        "--save",
        type=str,
        default=None,
        metavar="FILEPATH",
        help="Path to save the output. If not provided, output goes to stdout.",
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default=None,
        help="Path to the ML model for maliciousness prediction.",
    )
    parser.add_argument(
        "--tokenizer-path",
        type=str,
        default=None,
        help="Path to the tokenizer for the ML model.",
    )
    parser.add_argument(
        "--malicious-threshold",
        type=float,
        default=0.5,
        help="Threshold for classifying as malicious in reports (0.0 to 1.0).",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 2.6")

    args: argparse.Namespace = parser.parse_args()
    input_path_obj: Path = Path(args.path)

    # Step 1: Initialize models
    progress("Step 1: Initializing ML models...")
    try:
        MalwiObject.load_models_into_memory(
            distilbert_model_path=args.model_path, tokenizer_path=args.tokenizer_path
        )
        success("ML models initialized successfully")
    except Exception as e:
        model_warning("ML", e)

    if not input_path_obj.exists():
        path_error(input_path_obj)
        sys.exit(1)

    # Process input and collect all data
    csv_writer_instance: Optional[CSVWriter] = None

    try:
        # Handle CSV output separately for streaming
        if args.format == "csv" and args.save:
            progress("Step 2: Setting up CSV output stream...")
            save_path = Path(args.save)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            csv_writer_instance = CSVWriter(save_path)
            info(f"CSV output will be appended to: {save_path.resolve()}")

            # Process files and write directly to CSV
            progress("Step 3: Processing Python files for CSV export...")
            result = process_files(
                input_path_obj,
                accepted_extensions=["py"],
                predict=False,
                predict_svm=False,  # Performance
                retrieve_source_code=False,
                silent=False,
            )

            if result.all_objects:
                progress("Step 4: Writing objects to CSV file...")
                csv_writer_instance.write_objects(result.all_objects)
                success(f"Successfully wrote {len(result.all_objects)} objects to CSV")

            csv_writer_instance.close()
            success(f"CSV processing completed: {save_path.resolve()}")

        else:
            # For all other formats, collect data first
            progress("Step 2: Processing Python files with ML prediction...")
            result = process_files(
                input_path_obj,
                accepted_extensions=["py"],
                predict=True,
                retrieve_source_code=True,
                silent=False,
                malicious_threshold=args.malicious_threshold,
            )

            # Handle output
            progress("Step 3: Preparing output format...")
            output_file = None
            output_stream = sys.stdout

            if args.save:
                save_path = Path(args.save)
                save_path.parent.mkdir(parents=True, exist_ok=True)
                output_file = open(save_path, "w", encoding="utf-8", errors="replace")
                output_stream = output_file
                info(f"Output will be saved to: {save_path.resolve()}")

            progress(f"Step 4: Generating {args.format.upper()} report...")
            try:
                if args.format == "csv":
                    result.to_report_csv(output_stream)
                elif args.format == "json":
                    output_stream.write(result.to_report_json() + "\n")
                elif args.format == "yaml":
                    output_stream.write(result.to_report_yaml() + "\n")
                success(f"Report generation completed in {args.format.upper()} format")
            finally:
                if output_file:
                    output_file.close()

    except Exception as e:
        critical(f"A critical error occurred: {e}")
        import traceback

        # Print traceback to stderr directly for debugging
        traceback.print_exc(file=sys.stderr)
        if csv_writer_instance:
            csv_writer_instance.close()
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()

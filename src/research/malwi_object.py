import yaml
import json
import types
import base64
import inspect
import hashlib
import binascii

from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Any, Dict, Union


from research.mapping import SpecialCases, tokenize_code_type, COMMON_TARGET_FILES
from research.predict import get_node_text_prediction, initialize_models


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
    codeType: Optional[types.CodeType] = None

    def __init__(
        self,
        name: str,
        language: str,
        file_path: str,
        file_source_code: str,
        codeType: types.CodeType = None,
        warnings: List[str] = [],
    ):
        self.name = name
        self.file_path = file_path
        self.warnings = list(warnings)
        self.maliciousness = None
        self.codeType = codeType
        self.file_source_code = file_source_code

        if Path(self.file_path).name in COMMON_TARGET_FILES.get(language, []):
            self.warnings += [SpecialCases.TARGETED_FILE.value]

    @classmethod
    def load_models_into_memory(
        cls, model_path: Optional[str] = None, tokenizer_path: Optional[str] = None
    ) -> None:
        initialize_models(model_path=model_path, tokenizer_path=tokenizer_path)

    def to_tokens(self, map_special_tokens: bool = True) -> List[str]:
        all_token_parts: List[str] = []
        all_token_parts.extend(self.warnings)
        generated_instructions = tokenize_code_type(
            code_type=self.codeType, map_special_tokens=map_special_tokens
        )
        all_token_parts.extend(generated_instructions)
        return all_token_parts

    def to_token_string(self, map_special_tokens: bool = True) -> str:
        return " ".join(self.to_tokens(map_special_tokens=map_special_tokens))

    def to_string_hash(self) -> str:
        tokens = self.to_token_string()
        encoded_string = tokens.encode("utf-8")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(encoded_string)
        return sha256_hash.hexdigest()

    def retrieve_source_code(self) -> Optional[str]:
        try:
            self.code = inspect.getsource(self.codeType)
            return self.code
        except Exception:
            pass
        return None

    def predict(self) -> Optional[dict]:
        prediction = get_node_text_prediction(self.to_token_string())
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

    @staticmethod
    def _generate_report_data(
        malwi_files: List["MalwiObject"],
        all_files: List[str],
        malicious_threshold: float = 0.5,
        number_of_skipped_files: int = 0,
        malicious_only: bool = False,
    ) -> Dict[str, Any]:
        processed_objects_count = len(malwi_files)
        total_maliciousness_score = 0.0
        malicious_objects_count = 0
        files_with_scores_count = 0

        for mf in malwi_files:
            if mf.maliciousness is None:
                mf.predict()

            if mf.maliciousness is not None:
                total_maliciousness_score += mf.maliciousness
                files_with_scores_count += 1
                if mf.maliciousness > malicious_threshold:
                    malicious_objects_count += 1

        summary_statistics = {
            "total_files": len(all_files),
            "skipped_files": number_of_skipped_files,
            "processed_objects": processed_objects_count,
            "malicious_objects": malicious_objects_count,
        }

        report_data = {
            "statistics": summary_statistics,
            "details": [],
            "sources": {},
        }

        for mf in malwi_files:
            if mf.maliciousness is not None:
                if mf.maliciousness > malicious_threshold:
                    # only retrieve code when needed for performance
                    mf.retrieve_source_code()
                    report_data["details"].append(mf.to_dict())
                    report_data["sources"][mf.file_path] = base64.b64encode(
                        mf.file_source_code.encode("utf-8")
                    ).decode("utf-8")
                elif not malicious_only:
                    # only retrieve code when needed for performance
                    mf.retrieve_source_code()
                    report_data["details"].append(mf.to_dict())
                    report_data["sources"][mf.file_path] = base64.b64encode(
                        mf.file_source_code.encode("utf-8")
                    ).decode("utf-8")
            elif not malicious_only:
                # only retrieve code when needed for performance
                mf.retrieve_source_code()
                report_data["details"].append(mf.to_dict())

        return report_data

    @classmethod
    def to_report_json(
        cls,
        malwi_files: List["MalwiObject"],
        all_files: List[str],
        malicious_threshold: float = 0.5,
        number_of_skipped_files: int = 0,
        malicious_only: bool = False,
    ) -> str:
        report_data = cls._generate_report_data(
            malwi_files,
            all_files,
            malicious_threshold,
            number_of_skipped_files,
            malicious_only=malicious_only,
        )
        return json.dumps(report_data, indent=4)

    @classmethod
    def to_report_yaml(
        cls,
        malwi_files: List["MalwiObject"],
        all_files: List[str],
        malicious_threshold: float = 0.5,
        number_of_skipped_files: int = 0,
        malicious_only: bool = False,
    ) -> str:
        report_data = cls._generate_report_data(
            malwi_files,
            all_files,
            malicious_threshold,
            number_of_skipped_files,
            malicious_only=malicious_only,
        )
        return yaml.dump(
            report_data, sort_keys=False, width=float("inf"), default_flow_style=False
        )

    @classmethod
    def to_report_markdown(
        cls,
        malwi_files: List["MalwiObject"],
        all_files: List[str],
        malicious_threshold: float = 0.5,
        number_of_skipped_files: int = 0,
        malicious_only: bool = False,
    ) -> str:
        report_data = cls._generate_report_data(
            malwi_files,
            all_files,
            malicious_threshold,
            number_of_skipped_files,
            malicious_only=malicious_only,
        )

        stats = report_data["statistics"]

        txt = "# Malwi Report\n\n"
        txt += f"- Files: {stats['total_files']}\n"
        txt += f"- Skipped: {stats['skipped_files']}\n"
        txt += f"- Processed Objects: {stats['processed_objects']}\n"
        txt += f"- Malicious Objects: {stats['malicious_objects']}\n\n"

        for file in report_data["details"]:
            txt += f"## {file['path']}\n"

            for object in file["contents"]:
                name = object["name"] if object["name"] else "<object>"
                score = object["score"]
                if score > malicious_threshold:
                    maliciousness = f"👹 {score}"
                else:
                    maliciousness = f"🟢 {score}"
                txt += f"- Object: {name}\n"
                txt += f"- Maliciousness: {maliciousness}\n\n"
                txt += "### Code\n"
                txt += f"```\n{object['code']}\n```\n\n"
                txt += "### Tokens\n"
                txt += f"```\n{object['tokens']}\n```\n"
            txt += "\n\n"

        return txt

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

                        codeType = None

                        malwi_object = cls(
                            name=name,
                            file_source_code=source,
                            language=language,
                            file_path=file_path_val,
                            warnings=warnings,
                            codeType=codeType,
                        )
                        malwi_objects.append(malwi_object)

        return malwi_objects

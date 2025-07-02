import io
import json
import yaml
import base64
import unittest

from typing import List
from pathlib import Path
from dataclasses import dataclass, field

from research.disassemble_python import MalwiReport


@dataclass
class MockMalwiObject:
    """A simplified mock of the MalwiObject for testing purposes."""

    name: str
    file_path: str
    maliciousness: float
    file_source_code: str = ""
    code: str = ""
    warnings: List[str] = field(default_factory=list)

    def to_token_string(self) -> str:
        return f"TOKEN_{self.name.upper()}"

    def to_string_hash(self) -> str:
        return f"hash_for_{self.name}"

    def retrieve_source_code(self):
        if not self.code:
            self.code = f"def {self.name}():\n    pass"

    def predict(self):
        pass

    def to_dict(self) -> dict:
        code_display_value = self.code or "<source not available>"
        if "\n" in code_display_value:
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


class TestMalwiReport(unittest.TestCase):

    def setUp(self):
        """Set up common mock objects and reports for tests."""
        self.malicious_obj = MockMalwiObject(
            name="evil_func",
            file_path="/tmp/malware.py",
            maliciousness=0.95,
            file_source_code="import os; os.system('rm -rf /')",
            code="os.system('rm -rf /')",
        )
        self.benign_obj = MockMalwiObject(
            name="safe_func",
            file_path="/tmp/script.py",
            maliciousness=0.10,
            file_source_code="print('hello')",
            code="print('hello')",
        )
        self.all_objects = [self.malicious_obj, self.benign_obj]

        self.malicious_report = MalwiReport(
            all_objects=self.all_objects,
            malicious_objects=[self.malicious_obj],
            threshold=0.7,
            all_files=[Path("/tmp/malware.py"), Path("/tmp/script.py")],
            skipped_files=[],
            processed_files=2,
            malicious=True,
            confidence=0.88,
            activities=["SYSTEM_CALL", "FILE_OPERATION"],
        )

        self.benign_report = MalwiReport(
            all_objects=[self.benign_obj],
            malicious_objects=[],
            threshold=0.7,
            all_files=[Path("/tmp/script.py")],
            skipped_files=[],
            processed_files=1,
            malicious=False,
            confidence=0.99,
            activities=[],
        )

    def test_generate_report_data(self):
        """Test the internal data generation logic."""
        data = self.malicious_report._generate_report_data()

        stats = data["statistics"]
        self.assertEqual(stats["total_files"], 2)
        self.assertEqual(stats["processed_objects"], 2)
        self.assertEqual(stats["malicious_objects"], 1)

        self.assertEqual(len(data["details"]), 1)
        self.assertEqual(data["details"][0]["path"], self.malicious_obj.file_path)
        self.assertEqual(
            data["details"][0]["contents"][0]["name"], self.malicious_obj.name
        )

        self.assertIn(self.malicious_obj.file_path, data["sources"])
        decoded_source = base64.b64decode(
            data["sources"][self.malicious_obj.file_path]
        ).decode("utf-8")
        self.assertEqual(decoded_source, self.malicious_obj.file_source_code)

    def test_to_report_csv(self):
        """Test CSV report generation."""
        string_io = io.StringIO()
        self.malicious_report.to_report_csv(string_io)
        # FIX: Use splitlines() to robustly handle line endings (\n or \r\n).
        output = string_io.getvalue().strip().splitlines()

        self.assertEqual(len(output), 3)
        self.assertEqual(output[0], "tokens,hash,filepath")
        self.assertIn("TOKEN_EVIL_FUNC,hash_for_evil_func,/tmp/malware.py", output[1])
        self.assertIn("TOKEN_SAFE_FUNC,hash_for_safe_func,/tmp/script.py", output[2])

    def test_to_report_json(self):
        """Test JSON report generation."""
        json_str = self.malicious_report.to_report_json()
        data = json.loads(json_str)

        self.assertEqual(data["statistics"]["malicious_objects"], 1)
        self.assertEqual(len(data["details"]), 1)
        self.assertEqual(data["details"][0]["contents"][0]["name"], "evil_func")

    def test_to_report_yaml(self):
        """Test YAML report generation."""
        yaml_str = self.malicious_report.to_report_yaml()
        data = yaml.safe_load(yaml_str)

        self.assertEqual(data["statistics"]["malicious_objects"], 1)
        self.assertEqual(len(data["details"]), 1)
        self.assertEqual(data["details"][0]["contents"][0]["name"], "evil_func")
        self.assertIn("sources", data)

    def test_to_demo_text_malicious(self):
        """Test the simple text output for a malicious report."""
        text = self.malicious_report.to_demo_text()
        self.assertIn("- files: 2", text)
        self.assertIn("malicious: 1", text)
        self.assertIn("system call", text)
        self.assertIn("=> 👹 malicious 0.88", text)

    def test_to_demo_text_benign(self):
        """Test the simple text output for a benign report."""
        text = self.benign_report.to_demo_text()
        self.assertIn("- files: 1", text)
        self.assertIn("objects: 1", text)
        self.assertIn("good", text)

    def test_to_report_markdown(self):
        """Test Markdown report generation."""
        md = self.malicious_report.to_report_markdown()

        self.assertIn("# Malwi Report", md)
        self.assertIn("> 👹 **Malicious**: `0.88`", md)
        self.assertIn("- Malicious Objects: 1", md)

        self.assertIn("## Token Statistics", md)
        self.assertIn("- system call", md)

        self.assertIn("## /tmp/malware.py", md)
        self.assertIn("- Object: `evil_func`", md)
        self.assertIn("- Maliciousness: 👹 `0.95`", md)
        self.assertIn("```\nos.system('rm -rf /')\n```", md)

        self.assertNotIn("## /tmp/script.py", md)
        self.assertNotIn("safe_func", md)


if __name__ == "__main__":
    unittest.main(argv=["first-arg-is-ignored"], exit=False)

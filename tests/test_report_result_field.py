"""Test the result field in MalwiReport._generate_report_data()."""

import pytest
from pathlib import Path
from research.disassemble_python import MalwiReport, MalwiObject


class TestReportResultField:
    """Test suite for the result field in report data."""
    
    def test_result_good(self):
        """Test result is 'good' when no malicious objects."""
        report = MalwiReport(
            all_objects=[],
            malicious_objects=[],
            threshold=0.7,
            all_files=[],
            skipped_files=[],
            processed_files=0,
            malicious=False,
            confidence=1.0,
            activities=[],
        )
        
        data = report._generate_report_data()
        assert data["result"] == "good"
    
    def test_result_suspicious(self):
        """Test result is 'suspicious' when has malicious objects but not flagged malicious."""
        mock_obj = MalwiObject(
            name='test',
            language='python',
            file_path='test.py',
            file_source_code='',
        )
        mock_obj.maliciousness = 0.8
        
        report = MalwiReport(
            all_objects=[mock_obj],
            malicious_objects=[mock_obj],
            threshold=0.7,
            all_files=[Path('test.py')],
            skipped_files=[],
            processed_files=1,
            malicious=False,  # Not flagged as malicious overall
            confidence=0.6,
            activities=[],
        )
        
        data = report._generate_report_data()
        assert data["result"] == "suspicious"
    
    def test_result_malicious(self):
        """Test result is 'malicious' when flagged as malicious."""
        mock_obj = MalwiObject(
            name='test',
            language='python',
            file_path='test.py',
            file_source_code='',
        )
        mock_obj.maliciousness = 0.9
        
        report = MalwiReport(
            all_objects=[mock_obj],
            malicious_objects=[mock_obj],
            threshold=0.7,
            all_files=[Path('test.py')],
            skipped_files=[],
            processed_files=1,
            malicious=True,  # Flagged as malicious
            confidence=0.95,
            activities=['FILESYSTEM_ACCESS', 'NETWORK_HTTP_REQUEST'],
        )
        
        data = report._generate_report_data()
        assert data["result"] == "malicious"
    
    def test_result_in_json_output(self):
        """Test result field appears in JSON output."""
        report = MalwiReport(
            all_objects=[],
            malicious_objects=[],
            threshold=0.7,
            all_files=[],
            skipped_files=[],
            processed_files=0,
            malicious=False,
            confidence=1.0,
            activities=[],
        )
        
        json_output = report.to_report_json()
        assert '"result": "good"' in json_output
    
    def test_result_in_yaml_output(self):
        """Test result field appears in YAML output."""
        report = MalwiReport(
            all_objects=[],
            malicious_objects=[],
            threshold=0.7,
            all_files=[],
            skipped_files=[],
            processed_files=0,
            malicious=False,
            confidence=1.0,
            activities=[],
        )
        
        yaml_output = report.to_report_yaml()
        assert 'result: good' in yaml_output
    
    def test_result_in_markdown_output(self):
        """Test result classifications appear correctly in markdown output."""
        # Test good result
        good_report = MalwiReport(
            all_objects=[],
            malicious_objects=[],
            threshold=0.7,
            all_files=[],
            skipped_files=[],
            processed_files=0,
            malicious=False,
            confidence=1.0,
            activities=[],
        )
        markdown = good_report.to_report_markdown()
        assert '> 🟢 **Good**:' in markdown
        
        # Test suspicious result
        mock_obj = MalwiObject(
            name='test',
            language='python',
            file_path='test.py',
            file_source_code='',
        )
        mock_obj.maliciousness = 0.8
        
        suspicious_report = MalwiReport(
            all_objects=[mock_obj],
            malicious_objects=[mock_obj],
            threshold=0.7,
            all_files=[Path('test.py')],
            skipped_files=[],
            processed_files=1,
            malicious=False,
            confidence=0.6,
            activities=[],
        )
        markdown = suspicious_report.to_report_markdown()
        assert '> ⚠️  **Suspicious**:' in markdown
        assert 'Found 1 malicious objects but overall classification is not malicious' in markdown
        
        # Test malicious result
        malicious_report = MalwiReport(
            all_objects=[mock_obj],
            malicious_objects=[mock_obj],
            threshold=0.7,
            all_files=[Path('test.py')],
            skipped_files=[],
            processed_files=1,
            malicious=True,
            confidence=0.95,
            activities=[],
        )
        markdown = malicious_report.to_report_markdown()
        assert '> 👹 **Malicious**:' in markdown
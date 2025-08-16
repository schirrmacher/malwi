"""
First Responder Agent for initial malware triage decisions.
"""

import json
import os
import warnings
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

import autogen
from autogen import ConversableAgent

from common.messaging import info, success, warning, error


@dataclass
class TriageDecision:
    """Represents a triage decision for a file."""

    file_path: str
    decision: str  # "benign", "suspicious", "malicious"
    reasoning: str


class FirstResponder:
    """
    First Responder Agent that analyzes concatenated malicious files
    and makes initial triage decisions using AG2 with Mistral.
    """

    def __init__(self, api_key: str, model: str = "mistral-medium-2508"):
        """
        Initialize the First Responder agent.

        Args:
            api_key: Mistral API key
            model: Model name to use for analysis
        """
        self.api_key = api_key
        self.model = model
        self.agent = None

        if not api_key or api_key == "demo":
            error("Valid API key required for triage analysis")
            return

        # Set up AG2 configuration for Mistral
        os.environ["MISTRAL_API_KEY"] = api_key

        try:
            # Suppress AG2 warnings during initialization
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                from autogen import LLMConfig

                llm_config = LLMConfig(
                    api_type="mistral",
                    model=model,
                    api_key=api_key,
                    temperature=0.1,
                    max_tokens=4000,
                )

                self.agent = ConversableAgent(
                    name="MalwareAnalyst",
                    system_message="""You are a malware analysis expert specializing in Python code triage. 
Your task is to analyze potentially malicious Python files and categorize each one as:

- benign: Code appears safe, likely false positive from scanner
- suspicious: Code has concerning patterns but may not be definitively malicious  
- malicious: Code contains clear malicious behavior (data exfiltration, backdoors, etc.)

For each file, provide:
1. Decision (benign/suspicious/malicious)
2. Brief reasoning (2-3 sentences explaining why)

Respond ONLY with valid JSON in this exact format:
{
  "decisions": [
    {
      "file_path": "path/to/file",
      "decision": "malicious",
      "reasoning": "Contains clear backdoor with command execution and data exfiltration to remote server."
    }
  ]
}""",
                    llm_config=llm_config,
                    human_input_mode="NEVER",
                    max_consecutive_auto_reply=1,
                )
            pass  # Agent initialized successfully
        except Exception as e:
            self.agent = None

    def analyze_files(self, llm_content: str) -> List[TriageDecision]:
        """
        Analyze the concatenated file content and make triage decisions.

        Args:
            llm_content: Concatenated content from malicious files

        Returns:
            List of triage decisions for each file
        """
        if not self.agent:
            return self._fallback_analysis(llm_content)

        # Create analysis prompt
        user_prompt = f"""Analyze these Python files that were flagged as malicious by malwi scanner:

{llm_content}

Provide your triage decisions in the specified JSON format."""

        try:
            # Use AG2 to analyze the content
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                response = self.agent.generate_reply(
                    messages=[{"role": "user", "content": user_prompt}]
                )

            if not response:
                info("No response from LLM - using fallback")
                return self._fallback_analysis(llm_content)

            # Parse response
            try:
                # Handle different response formats
                if hasattr(response, "content"):
                    response_text = response.content
                elif isinstance(response, dict) and "content" in response:
                    response_text = response["content"]
                else:
                    response_text = str(response)

                # Debug logging removed for cleaner output

                # Handle markdown code blocks
                if "```json" in response_text:
                    json_start = response_text.find("```json") + 7
                    json_end = response_text.find("```", json_start)
                    if json_end != -1:
                        json_text = response_text[json_start:json_end].strip()
                    else:
                        info("Malformed JSON markdown block - using fallback")
                        return self._fallback_analysis(llm_content)
                else:
                    # Fallback to finding raw JSON
                    json_start = response_text.find("{")
                    json_end = response_text.rfind("}") + 1

                    if json_start == -1 or json_end == 0:
                        info("No JSON found in LLM response - using fallback")
                        return self._fallback_analysis(llm_content)

                    json_text = response_text[json_start:json_end]
                response_data = json.loads(json_text)

                decisions = []
                for decision_data in response_data.get("decisions", []):
                    decision = TriageDecision(
                        file_path=decision_data["file_path"],
                        decision=decision_data["decision"].upper(),
                        reasoning=decision_data["reasoning"],
                    )
                    decisions.append(decision)

                info(f"LLM provided {len(decisions)} triage decisions")
                return decisions

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                info(f"Failed to parse LLM response: {e} - using fallback")
                return self._fallback_analysis(llm_content)

        except Exception:
            return self._fallback_analysis(llm_content)

    def _fallback_analysis(self, llm_content: str) -> List[TriageDecision]:
        """
        Fallback analysis when LLM analysis fails.

        Args:
            llm_content: Concatenated file content

        Returns:
            Empty list since we require LLM for proper analysis
        """
        error("LLM analysis failed - cannot perform triage without AI reasoning")
        return []

    def process_triage_decisions(
        self,
        decisions: List[TriageDecision],
        source_files: List[Path],
        benign_folder: Path,
        suspicious_folder: Path,
        malicious_folder: Path,
        base_path: Path,
    ) -> Dict[str, List[str]]:
        """
        Process triage decisions by moving files to appropriate folders.

        Args:
            decisions: List of triage decisions
            source_files: List of source file paths to move
            benign_folder: Path to benign folder
            suspicious_folder: Path to suspicious folder
            malicious_folder: Path to malicious folder
            base_path: Base path for calculating relative paths

        Returns:
            Dictionary with moved file counts per category
        """
        import shutil

        # Create folders
        benign_folder.mkdir(parents=True, exist_ok=True)
        suspicious_folder.mkdir(parents=True, exist_ok=True)
        malicious_folder.mkdir(parents=True, exist_ok=True)

        # Create decision lookup by file path
        decision_map = {d.file_path: d for d in decisions}

        moved_files = {"benign": [], "suspicious": [], "malicious": []}

        for source_file in source_files:
            source_str = str(source_file)
            decision = decision_map.get(source_str)

            if not decision:
                warning(
                    f"No decision found for {source_file}, defaulting to suspicious"
                )
                target_folder = suspicious_folder
                category = "suspicious"
            else:
                # Map decision to folder (case insensitive)
                decision_lower = decision.decision.lower()
                if decision_lower == "benign":
                    target_folder = benign_folder
                    category = "benign"
                elif decision_lower == "malicious":
                    target_folder = malicious_folder
                    category = "malicious"
                else:  # suspicious
                    target_folder = suspicious_folder
                    category = "suspicious"

            try:
                # Calculate relative path and copy file
                rel_path = source_file.relative_to(base_path)
                dest_file = target_folder / rel_path
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_file, dest_file)

                moved_files[category].append(str(source_file))

            except Exception as e:
                error(f"Failed to move {source_file}: {e}")

        return moved_files

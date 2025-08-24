"""
First Responder Agent for initial malware triage decisions using AutoGen.
"""

import json
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass

from autogen import AssistantAgent

from common.messaging import warning, error


@dataclass
class TriageDecision:
    """Represents a triage decision for a folder."""

    decision: str  # "benign", "suspicious", "malicious"
    reasoning: str


class FirstResponder:
    """
    First Responder Agent that analyzes files using AutoGen AssistantAgent with Mistral.
    """

    def __init__(
        self, api_key: str, model: str = "mistral-large-2411", base_url: str = None
    ):
        """
        Initialize the First Responder agent.

        Args:
            api_key: API key for the LLM service
            model: Model name to use for analysis
            base_url: Base URL for the LLM API (auto-derived if None)
        """
        self.api_key = api_key
        self.model = model
        self.base_url = self._derive_base_url(model, base_url)

        if not api_key:
            error("Valid API key required for triage analysis")
            self.agent = None
            return

        # Configure for AutoGen
        config_list = [
            {
                "model": model,
                "api_key": api_key,
                "base_url": self.base_url,
            }
        ]

        system_message = """You are a malware analysis expert. Analyze ALL the provided code files together and give a single decision for the entire folder:
- benign: All files appear safe, likely false positives
- suspicious: Some files have concerning patterns but not definitively malicious
- malicious: Contains clear malicious behavior

Respond with JSON only: {"decision": "malicious", "reasoning": "brief reason for the entire folder"}

Example response:
{"decision": "malicious", "reasoning": "Contains base64 encoded payload and remote execution commands"}

Do not include any other text, explanations, or markdown formatting. Only JSON."""

        try:
            # Create AutoGen AssistantAgent
            self.agent = AssistantAgent(
                name="MalwareAnalyst",
                system_message=system_message,
                llm_config={
                    "config_list": config_list,
                    "temperature": 0.1,
                    "max_tokens": 500,
                    "timeout": 30,
                },
                human_input_mode="NEVER",
            )
        except Exception as e:
            error(f"Failed to initialize AutoGen agent: {e}")
            self.agent = None

    def _derive_base_url(self, model: str, base_url: str = None) -> str:
        """
        Derive the base URL for the LLM API based on the model name.

        Args:
            model: Model name
            base_url: Explicit base URL (if provided)

        Returns:
            Base URL for the API
        """
        if base_url:
            return base_url

        # Smart derivation based on model name
        model_lower = model.lower()

        if "mistral" in model_lower:
            return "https://api.mistral.ai/v1"
        elif "openai" in model_lower or "gpt" in model_lower:
            return "https://api.openai.com/v1"
        elif "claude" in model_lower or "anthropic" in model_lower:
            return "https://api.anthropic.com/v1"
        elif "llama" in model_lower or "meta" in model_lower:
            return "https://api.together.xyz/v1"
        elif "gemini" in model_lower or "google" in model_lower:
            return "https://generativelanguage.googleapis.com/v1"
        else:
            # Default to Mistral for unknown models
            return "https://api.mistral.ai/v1"

    def analyze_files_sync(self, llm_content: str) -> TriageDecision:
        """
        Analyze the concatenated file content and make a triage decision.

        Args:
            llm_content: Concatenated content from files

        Returns:
            Single triage decision for the folder
        """
        if not self.agent:
            error("Agent not initialized - API key required")
            return TriageDecision(
                decision="suspicious", reasoning="No API key provided"
            )

        try:
            # Create a simple user proxy to send the message
            from autogen import UserProxyAgent

            user_proxy = UserProxyAgent(
                name="User",
                human_input_mode="NEVER",
                max_consecutive_auto_reply=1,
                is_termination_msg=lambda x: True,  # Always terminate after one response
                code_execution_config=False,  # Disable code execution
            )

            # Send analysis request
            message = f"Analyze these files:\n\n{llm_content}"

            # Initiate chat
            result = user_proxy.initiate_chat(
                self.agent, message=message, max_turns=1, silent=True
            )

            # Extract response from chat history
            if result and hasattr(result, "chat_history") and result.chat_history:
                last_message = result.chat_history[-1]
                content = last_message.get("content", "")
            elif result and hasattr(result, "summary"):
                content = result.summary
            else:
                # Fallback: get last message from agent's chat history
                if hasattr(self.agent, "_oai_messages") and self.agent._oai_messages:
                    content = self.agent._oai_messages[-1].get("content", "")
                else:
                    content = ""

            if not content:
                error("No response content from agent")
                return TriageDecision(
                    decision="suspicious", reasoning="No response from agent"
                )

            # Extract JSON from response
            json_start = content.find("{")
            json_end = content.rfind("}") + 1

            if json_start >= 0 and json_end > 0:
                json_text = content[json_start:json_end]
                result_data = json.loads(json_text)

                return TriageDecision(
                    decision=result_data.get("decision", "suspicious"),
                    reasoning=result_data.get("reasoning", "Unable to determine"),
                )
            else:
                error(f"No valid JSON found in response: {content[:100]}...")
                return TriageDecision(
                    decision="suspicious", reasoning="Invalid response format"
                )

        except json.JSONDecodeError as e:
            error(f"Failed to parse JSON response: {e}")
            return TriageDecision(
                decision="suspicious", reasoning=f"JSON parse error: {str(e)}"
            )
        except Exception as e:
            error(f"Error during analysis: {e}")
            return TriageDecision(
                decision="suspicious", reasoning=f"Analysis error: {str(e)}"
            )

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

        moved_files = {"benign": [], "suspicious": [], "malicious": []}

        for i, source_file in enumerate(source_files):
            if i < len(decisions):
                decision = decisions[i]
            else:
                warning(f"No decision for {source_file}, defaulting to suspicious")
                decision = TriageDecision(
                    decision="suspicious", reasoning="No decision available"
                )

            # Map decision to folder
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

"""
First Responder Agent for initial malware triage decisions using AutoGen.
"""

from pathlib import Path
from typing import Dict, List

from typing import Literal
from pydantic import Field
from autogen_agentchat.agents import AssistantAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_core.models import ModelInfo, ModelFamily
from pydantic import BaseModel

from common.messaging import warning, error


class TriageDecision(BaseModel):
    """Pydantic model for triage decisions."""

    model_config = {"extra": "forbid"}  # This adds additionalProperties: false

    decision: Literal["benign", "suspicious", "malicious"]
    reasoning: str
    file_extracts: Dict[str, str] = Field(
        default_factory=dict, json_schema_extra={"additionalProperties": False}
    )


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

        system_message = """You are a malware analysis expert. Analyze ALL the provided code files together and give a single decision for the entire folder:
- benign: All files appear safe, likely false positives
- suspicious: Some files have concerning patterns but not definitively malicious
- malicious: Contains clear malicious behavior"""

        try:
            model_client = OpenAIChatCompletionClient(
                model=model,
                api_key=api_key,
                base_url=self.base_url,
                model_info=ModelInfo(
                    family=ModelFamily.MISTRAL,
                    json_output=True,
                    function_calling=False,
                    vision=False,
                    structured_output=True,
                ),
                # Add Mistral-specific JSON mode parameters
                create_args={"response_format": {"type": "json_object"}},
            )

            # Create AssistantAgent with structured output following cookbook
            self.agent = AssistantAgent(
                name="MalwareAnalyst",
                model_client=model_client,
                system_message=system_message,
                output_content_type=TriageDecision,
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

    async def analyze_files_sync(self, llm_content: str) -> TriageDecision:
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
            # Send analysis request using structured output without console output
            message = f"Analyze these files:\n\n{llm_content}"
            stream = self.agent.run_stream(task=message)
            result = None
            async for chunk in stream:
                result = chunk

            # Extract the structured response from the last message
            if result and result.messages:
                structured_result = result.messages[-1].content
                # With structured output, this should be a TriageDecision object
                if isinstance(structured_result, TriageDecision):
                    return structured_result
                # If it's a string, try to parse it
                elif isinstance(structured_result, str):
                    try:
                        import json

                        data = json.loads(structured_result)
                        return TriageDecision.model_validate(data)
                    except Exception:
                        # JSON parsing failed, return a safe fallback decision based on content
                        if "malicious" in structured_result.lower():
                            return TriageDecision(
                                decision="malicious",
                                reasoning="Malicious behavior detected (JSON parsing fallback)",
                            )
                        elif "benign" in structured_result.lower():
                            return TriageDecision(
                                decision="benign",
                                reasoning="No malicious behavior detected (JSON parsing fallback)",
                            )
                        else:
                            return TriageDecision(
                                decision="suspicious",
                                reasoning="Potential issues detected (JSON parsing fallback)",
                            )

            return TriageDecision(
                decision="suspicious", reasoning="No structured response received"
            )

        except Exception as e:
            error(f"Error during analysis: {e}")
            return TriageDecision(
                decision="suspicious", reasoning=f"Analysis error: {str(e)}"
            )

    async def analyze_files_sync_smart(self, llm_content: str) -> TriageDecision:
        """
        Analyze the concatenated file content and make a triage decision with malicious code extraction.

        Args:
            llm_content: Concatenated content from files

        Returns:
            Single triage decision for the folder with extracted malicious code
        """
        if not self.agent:
            error("Agent not initialized - API key required")
            return TriageDecision(
                decision="suspicious", reasoning="No API key provided"
            )

        try:
            # Create smart system message for malicious code extraction
            smart_system_message = """You are a malware analysis expert. Analyze ALL the provided code files together and give a single decision for the entire folder:
- benign: All files appear safe, likely false positives  
- suspicious: Some files have concerning patterns but not definitively malicious
- malicious: Contains clear malicious behavior

Leave the file_extracts field empty - file extraction will be handled separately."""

            # Create smart agent following cookbook example
            from autogen_core.models import ModelInfo, ModelFamily

            smart_model_client = OpenAIChatCompletionClient(
                model=self.model,
                api_key=self.api_key,
                base_url=self.base_url,
                model_info=ModelInfo(
                    family=ModelFamily.MISTRAL,
                    json_output=True,
                    function_calling=False,
                    vision=False,
                    structured_output=True,
                ),
                # Add Mistral-specific JSON mode parameters
                create_args={"response_format": {"type": "json_object"}},
            )

            smart_agent = AssistantAgent(
                name="SmartMalwareAnalyst",
                model_client=smart_model_client,
                system_message=smart_system_message,
                output_content_type=TriageDecision,
            )

            # Send analysis request using structured output without console output
            message = f"Analyze these files:\n\n{llm_content}"
            stream = smart_agent.run_stream(task=message)
            result = None
            async for chunk in stream:
                result = chunk

            # Extract the structured response from the last message
            if result and result.messages:
                structured_result = result.messages[-1].content
                # With structured output, this should be a TriageDecision object
                if isinstance(structured_result, TriageDecision):
                    return structured_result
                # If it's a string, try to parse it
                elif isinstance(structured_result, str):
                    try:
                        import json

                        data = json.loads(structured_result)
                        return TriageDecision.model_validate(data)
                    except Exception:
                        # JSON parsing failed, return a safe fallback decision based on content
                        if "malicious" in structured_result.lower():
                            return TriageDecision(
                                decision="malicious",
                                reasoning="Malicious behavior detected (JSON parsing fallback)",
                            )
                        elif "benign" in structured_result.lower():
                            return TriageDecision(
                                decision="benign",
                                reasoning="No malicious behavior detected (JSON parsing fallback)",
                            )
                        else:
                            return TriageDecision(
                                decision="suspicious",
                                reasoning="Potential issues detected (JSON parsing fallback)",
                            )

            return TriageDecision(
                decision="suspicious", reasoning="No structured response received"
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

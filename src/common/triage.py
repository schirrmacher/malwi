"""
Triage functionality for analyzing files with LLM models and organizing them.
"""

import shutil
from pathlib import Path
from typing import Dict

from common.messaging import info, warning, error, success
from cli.agents.first_responder import FirstResponder


def run_triage(
    input_path: str,
    llm_model: str,
    api_key: str,
    base_url: str = None,
    output_dir: str = "triaged",
    benign_folder: str = "benign",
    suspicious_folder: str = "suspicious",
    malicious_folder: str = "malicious",
) -> None:
    """
    Run triage on the specified input path using FirstResponder agent.
    Iterates through immediate child folders and organizes files into
    benign/suspicious/malicious folders.

    Args:
        input_path: Path to directory containing folders to triage
        llm_model: LLM model to use for analysis
        api_key: API key for the LLM service
        base_url: Base URL for the LLM API (auto-derived if None)
        output_dir: Output directory name for triage results
        benign_folder: Name of folder for benign files
        suspicious_folder: Name of folder for suspicious files
        malicious_folder: Name of folder for malicious files
    """
    path = Path(input_path)

    if not path.exists():
        raise ValueError(f"Path does not exist: {input_path}")

    if not path.is_dir():
        raise ValueError(f"Path must be a directory: {input_path}")

    # Initialize FirstResponder agent
    first_responder = FirstResponder(api_key, llm_model, base_url)

    # Create output folders - independent from input directory
    output_base = Path(output_dir).resolve()
    benign_path = output_base / benign_folder
    suspicious_path = output_base / suspicious_folder
    malicious_path = output_base / malicious_folder

    # Clean and create folders
    if output_base.exists():
        shutil.rmtree(output_base)
    benign_path.mkdir(parents=True, exist_ok=True)
    suspicious_path.mkdir(parents=True, exist_ok=True)
    malicious_path.mkdir(parents=True, exist_ok=True)

    # Get immediate child directories
    child_dirs = [d for d in path.iterdir() if d.is_dir()]

    if not child_dirs:
        info("No subdirectories found - analyzing files in root directory")
        child_dirs = [path]

    info(f"Processing {len(child_dirs)} directories")

    total_stats = {"benign": 0, "suspicious": 0, "malicious": 0}

    # Process each child directory
    for child_dir in child_dirs:
        info(f"\nAnalyzing folder: {child_dir.name}")

        # Collect Python and JavaScript files
        files_to_analyze = []
        extensions = [".py", ".js", ".mjs", ".cjs"]

        for ext in extensions:
            files_to_analyze.extend(list(child_dir.rglob(f"*{ext}")))

        if not files_to_analyze:
            info(f"  No files to analyze in {child_dir.name}")
            continue

        info(f"  Found {len(files_to_analyze)} files")

        # Read and concatenate file contents
        concatenated_content = ""
        file_map = {}  # Map file content markers to actual paths

        for file_path in files_to_analyze:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    # Clean content of control characters that can break JSON
                    import re

                    content = re.sub(r"[\x00-\x1f\x7f]", "", content)
                    # Use relative path from child_dir for cleaner output
                    rel_path = file_path.relative_to(child_dir)
                    file_marker = f"{child_dir.name}/{rel_path}"
                    concatenated_content += f"\n### FILE: {file_marker}\n{content}\n"
                    file_map[file_marker] = file_path
            except Exception as e:
                error(f"  Error reading {file_path}: {e}")
                continue

        if concatenated_content:
            # Analyze folder with FirstResponder - gets single decision for entire folder
            decision = first_responder.analyze_files_sync(concatenated_content)

            # Determine target folder based on decision
            decision_lower = decision.decision.lower()
            if decision_lower == "benign":
                target_folder = benign_path
                total_stats["benign"] += 1
                info(f"  ✓ BENIGN folder: {child_dir.name}")
                info(f"    Reasoning: {decision.reasoning}")
            elif decision_lower == "malicious":
                target_folder = malicious_path
                total_stats["malicious"] += 1
                error(f"  ⚠ MALICIOUS folder: {child_dir.name}")
                error(f"    Reasoning: {decision.reasoning}")
            else:  # suspicious
                target_folder = suspicious_path
                total_stats["suspicious"] += 1
                warning(f"  ? SUSPICIOUS folder: {child_dir.name}")
                warning(f"    Reasoning: {decision.reasoning}")

            # Copy entire folder to target location
            try:
                dest_folder = target_folder / child_dir.name
                if dest_folder.exists():
                    shutil.rmtree(dest_folder)
                shutil.copytree(child_dir, dest_folder)
            except Exception as e:
                error(f"  Failed to copy folder {child_dir.name}: {e}")

    # Print summary
    success(f"\n{'=' * 50}")
    success(f"Triage Complete - Folders organized in: {output_base}")
    success(f"{'=' * 50}")
    info(f"  Benign folders:     {total_stats['benign']} → {benign_path.name}/")
    warning(
        f"  Suspicious folders: {total_stats['suspicious']} → {suspicious_path.name}/"
    )
    if total_stats["malicious"] > 0:
        error(
            f"  Malicious folders:  {total_stats['malicious']} → {malicious_path.name}/"
        )
    else:
        info(
            f"  Malicious folders:  {total_stats['malicious']} → {malicious_path.name}/"
        )

#!/usr/bin/env python3
"""
Utility to fetch the current HuggingFace model commit hash and generate version mappings.
Run this after training/updating models to pin specific commits to malwi versions.
"""

import requests
import json
from typing import Dict, Optional
from pathlib import Path
import sys

def fetch_hf_commit_hash(repo_id: str, revision: str = "main") -> Optional[str]:
    """
    Fetch the current commit hash from a HuggingFace repository.
    
    Args:
        repo_id: HuggingFace repository ID (e.g., "schirrmacher/malwi")
        revision: Branch/tag name (default: "main")
    
    Returns:
        Commit hash string or None if failed
    """
    try:
        # Try multiple API endpoints
        endpoints = [
            f"https://huggingface.co/api/models/{repo_id}/revision/{revision}",
            f"https://huggingface.co/{repo_id}/raw/{revision}/README.md",  # This will redirect and show commit
            f"https://huggingface.co/api/models/{repo_id}",  # Get general repo info
        ]
        
        for i, url in enumerate(endpoints):
            try:
                if i == 1:  # For the raw file approach
                    response = requests.head(url, timeout=10, allow_redirects=True)
                    # Check if we can get commit info from headers or URL
                    if 'X-Repo-Commit' in response.headers:
                        commit_hash = response.headers['X-Repo-Commit']
                        print(f"✅ Found commit hash for {repo_id}@{revision}: {commit_hash}")
                        return commit_hash
                    continue
                
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                
                data = response.json()
                
                # Try different possible fields for commit hash
                commit_hash = data.get("sha") or data.get("id") or data.get("lastModified")
                
                if commit_hash:
                    print(f"✅ Found commit hash for {repo_id}@{revision}: {commit_hash}")
                    return commit_hash
                    
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                print(f"⚠️  Endpoint {i+1} failed: {e}")
                continue
        
        print(f"❌ Could not fetch commit hash from any endpoint for {repo_id}@{revision}")
        return None
        
    except Exception as e:
        print(f"❌ Unexpected error fetching commit hash for {repo_id}@{revision}: {e}")
        return None

def generate_version_mapping(repo_id: str, malwi_version: str, manual_commit: Optional[str] = None) -> Dict[str, str]:
    """
    Generate a version mapping dictionary for the current model state.
    
    Args:
        repo_id: HuggingFace repository ID
        malwi_version: Current malwi version
        manual_commit: Optional manual commit hash override
    
    Returns:
        Dictionary with repo and commit hash
    """
    if manual_commit:
        print(f"✅ Using manually provided commit hash: {manual_commit}")
        commit_hash = manual_commit
    else:
        commit_hash = fetch_hf_commit_hash(repo_id, "main")
        
        if not commit_hash or commit_hash == "main":
            print(f"\n⚠️  Could not automatically fetch commit hash.")
            print(f"💡 You can find the current commit hash at: https://huggingface.co/{repo_id}")
            print(f"🔗 Or check the commits page: https://huggingface.co/{repo_id}/commits/main")
            
            manual_input = input(f"📝 Enter commit hash manually (or press Enter for 'main'): ").strip()
            commit_hash = manual_input if manual_input else "main"
    
    return {
        "repo": repo_id,
        "revision": commit_hash
    }

def update_model_config_in_code(malwi_version: str, config: Dict[str, str]) -> None:
    """
    Update the model configuration in predict_distilbert.py
    
    Args:
        malwi_version: Malwi version to add/update
        config: Model configuration dictionary
    """
    predict_file = Path(__file__).parent.parent / "src" / "research" / "predict_distilbert.py"
    
    if not predict_file.exists():
        print(f"❌ Could not find {predict_file}")
        return
    
    # Read current file
    with open(predict_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Find the VERSION_TO_MODEL_CONFIG section
    start_marker = "VERSION_TO_MODEL_CONFIG = {"
    end_marker = "}"
    
    start_idx = content.find(start_marker)
    if start_idx == -1:
        print("❌ Could not find VERSION_TO_MODEL_CONFIG in predict_distilbert.py")
        return
    
    # Find the end of the dictionary
    brace_count = 0
    end_idx = start_idx + len(start_marker)
    
    for i, char in enumerate(content[start_idx + len(start_marker):], start_idx + len(start_marker)):
        if char == '{':
            brace_count += 1
        elif char == '}':
            if brace_count == 0:
                end_idx = i + 1
                break
            brace_count -= 1
    
    # Extract current config
    config_section = content[start_idx:end_idx]
    
    # Add new version entry
    new_entry = f'''        "{malwi_version}": {{
            "repo": "{config['repo']}",
            "revision": "{config['revision']}"  # Commit: {config['revision'][:7]}
        }},'''
    
    # Insert new entry at the beginning of the config (after the opening brace)
    insertion_point = start_idx + len(start_marker) + 1  # After "{"
    new_content = (
        content[:insertion_point] + 
        "\n" + new_entry + 
        content[insertion_point:]
    )
    
    # Write back to file
    with open(predict_file, "w", encoding="utf-8") as f:
        f.write(new_content)
    
    print(f"✅ Added version {malwi_version} to model configuration")
    print(f"   Repository: {config['repo']}")
    print(f"   Commit: {config['revision']}")

def main():
    """Main function"""
    if len(sys.argv) < 3:
        print("Usage: python fetch_hf_commit.py <repo_id> <malwi_version> [commit_hash]")
        print("Example: python fetch_hf_commit.py schirrmacher/malwi 0.0.21")
        print("         python fetch_hf_commit.py schirrmacher/malwi 0.0.21 abc123def456")
        sys.exit(1)
    
    repo_id = sys.argv[1]
    malwi_version = sys.argv[2]
    manual_commit = sys.argv[3] if len(sys.argv) > 3 else None
    
    if manual_commit:
        print(f"🔍 Using provided commit hash for {repo_id}: {manual_commit}")
    else:
        print(f"🔍 Fetching commit hash for {repo_id}...")
    
    config = generate_version_mapping(repo_id, malwi_version, manual_commit)
    
    print(f"\n📋 Generated configuration for malwi v{malwi_version}:")
    print(f"   Repository: {config['repo']}")
    print(f"   Commit: {config['revision']}")
    
    # Ask user if they want to update the code
    response = input(f"\n❓ Update predict_distilbert.py with this configuration? (y/N): ")
    
    if response.lower() in ['y', 'yes']:
        update_model_config_in_code(malwi_version, config)
        print(f"\n✅ Configuration updated! Commit hash {config['revision'][:7]} is now pinned to malwi v{malwi_version}")
    else:
        print(f"\n📋 Manual configuration (add to VERSION_TO_MODEL_CONFIG):")
        print(f'    "{malwi_version}": {{')
        print(f'        "repo": "{config["repo"]}",')
        print(f'        "revision": "{config["revision"]}"  # Commit: {config["revision"][:7]}')
        print(f'    }},')

if __name__ == "__main__":
    main()
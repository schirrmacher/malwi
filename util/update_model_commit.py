#!/usr/bin/env python3
"""
Utility to update the model commit hash in src/malwi/_version.py
Fetches the latest commit from HuggingFace and updates the __model_commit__ variable.
"""

import re
import sys
from pathlib import Path

try:
    from huggingface_hub import HfApi
except ImportError:
    print("Error: huggingface-hub is required. Install it with:")
    print("pip install huggingface-hub")
    sys.exit(1)


def get_latest_hf_commit(repo_name: str = "schirrmacher/malwi") -> str:
    """Get the latest commit hash from HuggingFace repository."""
    try:
        api = HfApi()
        info = api.repo_info(repo_name, repo_type='model')
        return info.sha
    except Exception as e:
        print(f"Error fetching commit from HuggingFace: {e}")
        return None


def update_version_file(commit_hash: str) -> bool:
    """Update the __model_commit__ in src/malwi/_version.py"""
    version_file = Path(__file__).parent.parent / "src" / "malwi" / "_version.py"
    
    if not version_file.exists():
        print(f"Error: Version file not found at {version_file}")
        return False
    
    try:
        # Read current content
        content = version_file.read_text()
        
        # Update the model commit hash
        pattern = r'__model_commit__ = "[^"]*"'
        replacement = f'__model_commit__ = "{commit_hash[:8]}"'
        
        new_content = re.sub(pattern, replacement, content)
        
        if new_content == content:
            print("Warning: No __model_commit__ found to update")
            return False
        
        # Write updated content
        version_file.write_text(new_content)
        
        print(f"✅ Updated __model_commit__ to {commit_hash[:8]} in {version_file}")
        return True
        
    except Exception as e:
        print(f"Error updating version file: {e}")
        return False


def main():
    """Main function."""
    print("🔄 Updating model commit hash...")
    
    # Get latest commit
    print("Fetching latest commit from HuggingFace...")
    commit_hash = get_latest_hf_commit()
    
    if not commit_hash:
        print("❌ Failed to fetch commit hash")
        return 1
    
    print(f"Latest commit: {commit_hash}")
    
    # Update version file
    if update_version_file(commit_hash):
        print("🎉 Model commit hash updated successfully!")
        print("\nNext steps:")
        print("1. Verify the change: git diff src/malwi/_version.py")
        print("2. Test the version: malwi --version")
        print("3. Commit the change: git add src/malwi/_version.py && git commit -m 'Update model commit hash'")
        return 0
    else:
        print("❌ Failed to update model commit hash")
        return 1


if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3
"""
Simple script to help get model information from HuggingFace.
Provides instructions and template code for pinning model versions.
"""

import sys
from pathlib import Path

def main():
    """Provide instructions for getting HuggingFace model commit hashes."""
    
    print("=" * 60)
    print("🤗 HuggingFace Model Version Pinning Guide")
    print("=" * 60)
    print()
    print("To get the commit hash for your model:")
    print()
    print("1. Visit your model page:")
    print("   https://huggingface.co/schirrmacher/malwi")
    print()
    print("2. Click on 'Files and versions' tab")
    print()
    print("3. Look for the commit hash (7-40 characters) next to 'main' or in the URL")
    print("   Example: abc123def456...")
    print()
    print("4. Or use the HuggingFace CLI:")
    print("   pip install huggingface-hub")
    print("   huggingface-cli repo info schirrmacher/malwi --repo-type model")
    print()
    print("5. Or use Python:")
    print("   from huggingface_hub import HfApi")
    print("   api = HfApi()")
    print("   info = api.repo_info('schirrmacher/malwi')")
    print("   print(f'Latest commit: {info.sha}')")
    print()
    print("=" * 60)
    print()
    
    if len(sys.argv) > 1:
        version = sys.argv[1]
        commit = sys.argv[2] if len(sys.argv) > 2 else "REPLACE_WITH_COMMIT_HASH"
        
        print(f"📝 Add this to VERSION_TO_MODEL_CONFIG in predict_distilbert.py:")
        print()
        print(f'        "{version}": {{')
        print(f'            "repo": "schirrmacher/malwi",')
        print(f'            "revision": "{commit}"  # Pinned to specific commit')
        print(f'        }},')
        print()
    else:
        print("Usage: python get_hf_model_info.py <version> [commit_hash]")
        print("Example: python get_hf_model_info.py 0.0.21 abc123def456")
        print()
        
    # Try to use huggingface_hub if available
    try:
        from huggingface_hub import HfApi
        print("🔍 Attempting to fetch current model info...")
        api = HfApi()
        try:
            info = api.repo_info('schirrmacher/malwi', repo_type='model')
            print(f"✅ Current model commit hash: {info.sha}")
            print(f"   Last modified: {info.lastModified}")
        except Exception as e:
            print(f"❌ Could not fetch: {e}")
            print("   The repository might be private or the name might be different.")
    except ImportError:
        print("💡 Tip: Install huggingface-hub for automatic fetching:")
        print("   pip install huggingface-hub")

if __name__ == "__main__":
    main()
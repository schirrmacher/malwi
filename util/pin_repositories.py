#!/usr/bin/env python3
"""
Utility to pin all repository URLs to specific commits for reproducible training data.
This script fetches the latest commit hashes from all repositories and generates
a pinned configuration file.
"""

import asyncio
import json
import logging
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

# Import the repository URLs from download_data
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from research.download_data import BENIGN_REPO_URLS, MALICIOUS_REPO_URLS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def get_repo_name_from_url(url: str) -> str:
    """Extract repository name from URL."""
    try:
        path_part = urlparse(url).path
        repo_name = path_part.strip("/").replace(".git", "")
        return repo_name.split("/")[-1] if "/" in repo_name else repo_name
    except Exception:
        return url.split("/")[-1].replace(".git", "")


def get_full_repo_path(url: str) -> str:
    """Extract full owner/repo path from URL."""
    try:
        path_part = urlparse(url).path
        repo_path = path_part.strip("/").replace(".git", "")
        # Remove leading slash and ensure format is owner/repo
        if repo_path.count("/") >= 1:
            parts = repo_path.split("/")
            return f"{parts[-2]}/{parts[-1]}"
        return repo_path
    except Exception:
        return url.split("/")[-2:] if "/" in url else url


async def get_commit_hash_git_ls_remote(url: str) -> Optional[str]:
    """Get latest commit hash using git ls-remote (faster than cloning)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "ls-remote", url, "HEAD",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode == 0:
            output = stdout.decode().strip()
            if output:
                commit_hash = output.split()[0]
                return commit_hash
        else:
            logging.warning(f"git ls-remote failed for {url}: {stderr.decode()}")
            return None
    except Exception as e:
        logging.error(f"Error getting commit hash for {url}: {e}")
        return None


async def fetch_commit_hash_with_fallback(url: str) -> Optional[str]:
    """Try git ls-remote first, fallback to shallow clone if needed."""
    # First try git ls-remote (fast)
    commit_hash = await get_commit_hash_git_ls_remote(url)
    if commit_hash:
        return commit_hash
    
    # Fallback to shallow clone
    logging.info(f"Fallback to shallow clone for {url}")
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", url, temp_dir + "/repo",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode == 0:
                # Get the commit hash
                proc2 = await asyncio.create_subprocess_exec(
                    "git", "rev-parse", "HEAD",
                    cwd=temp_dir + "/repo",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc2.communicate()
                
                if proc2.returncode == 0:
                    return stdout.decode().strip()
        except Exception as e:
            logging.error(f"Fallback clone failed for {url}: {e}")
    
    return None


async def process_repository_batch(repo_urls: List[str], batch_name: str) -> Dict[str, Dict[str, str]]:
    """Process a batch of repositories concurrently."""
    logging.info(f"Processing {len(repo_urls)} {batch_name} repositories...")
    
    results = {}
    
    # Process repositories with limited concurrency to avoid overwhelming servers
    semaphore = asyncio.Semaphore(10)  # Max 10 concurrent requests
    
    async def process_single_repo(url: str) -> None:
        async with semaphore:
            repo_name = get_repo_name_from_url(url)
            full_path = get_full_repo_path(url)
            
            logging.info(f"Fetching commit hash for {repo_name}...")
            commit_hash = await fetch_commit_hash_with_fallback(url)
            
            if commit_hash:
                results[url] = {
                    "repo_name": repo_name,
                    "full_path": full_path,
                    "commit_hash": commit_hash,
                    "url": url
                }
                logging.info(f"✅ {repo_name}: {commit_hash[:8]}")
            else:
                logging.error(f"❌ Failed to get commit hash for {repo_name}")
                results[url] = {
                    "repo_name": repo_name,
                    "full_path": full_path,
                    "commit_hash": None,
                    "url": url,
                    "error": "Failed to fetch commit hash"
                }
    
    # Run all repository processing concurrently
    tasks = [process_single_repo(url) for url in repo_urls]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    successful = sum(1 for r in results.values() if r.get("commit_hash"))
    failed = len(results) - successful
    
    logging.info(f"{batch_name} batch complete: {successful} success, {failed} failed")
    return results


async def main():
    """Main function to pin all repositories."""
    logging.info("🔄 Starting repository pinning process...")
    logging.info(f"Total repositories to process: {len(BENIGN_REPO_URLS)} benign + {len(MALICIOUS_REPO_URLS)} malicious")
    
    # Process benign repositories
    benign_results = await process_repository_batch(BENIGN_REPO_URLS, "benign")
    
    # Process malicious repositories  
    malicious_results = await process_repository_batch(MALICIOUS_REPO_URLS, "malicious")
    
    # Combine results
    all_results = {
        "metadata": {
            "generated_at": "2025-08-15",
            "total_repositories": len(BENIGN_REPO_URLS) + len(MALICIOUS_REPO_URLS),
            "benign_count": len(BENIGN_REPO_URLS),
            "malicious_count": len(MALICIOUS_REPO_URLS),
            "successful_benign": sum(1 for r in benign_results.values() if r.get("commit_hash")),
            "successful_malicious": sum(1 for r in malicious_results.values() if r.get("commit_hash")),
        },
        "benign_repositories": benign_results,
        "malicious_repositories": malicious_results,
    }
    
    # Save results to configuration file
    output_file = Path(__file__).parent / "pinned_repositories.json"
    with open(output_file, "w") as f:
        json.dump(all_results, f, indent=2, sort_keys=True)
    
    logging.info(f"📁 Pinned repository configuration saved to: {output_file}")
    
    # Print summary
    total_successful = all_results["metadata"]["successful_benign"] + all_results["metadata"]["successful_malicious"]
    total_repos = all_results["metadata"]["total_repositories"]
    
    print("\n" + "="*60)
    print("🎉 Repository Pinning Complete!")
    print("="*60)
    print(f"Total repositories: {total_repos}")
    print(f"Successfully pinned: {total_successful}")
    print(f"Failed: {total_repos - total_successful}")
    print(f"Success rate: {total_successful/total_repos*100:.1f}%")
    print(f"Configuration saved to: {output_file}")
    print("="*60)
    
    # List any failures for manual review
    failures = []
    for repo_data in {**benign_results, **malicious_results}.values():
        if not repo_data.get("commit_hash"):
            failures.append(repo_data)
    
    if failures:
        print(f"\n⚠️  {len(failures)} repositories failed:")
        for failure in failures[:10]:  # Show first 10 failures
            print(f"  - {failure['repo_name']}: {failure.get('error', 'Unknown error')}")
        if len(failures) > 10:
            print(f"  ... and {len(failures) - 10} more")


if __name__ == "__main__":
    asyncio.run(main())
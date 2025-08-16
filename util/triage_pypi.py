#!/usr/bin/env python3
"""
PyPI Package Triage Utility

Downloads the newest packages from PyPI and scans them with malwi,
moving suspicious findings to ../malwi-samples/python/suspicious for review.
"""

import argparse
import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

import requests
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def get_newest_pypi_packages(limit: int = 100) -> List[str]:
    """
    Get the newest packages from PyPI.
    
    Args:
        limit: Maximum number of packages to retrieve
        
    Returns:
        List of package names
    """
    logging.info(f"Fetching newest {limit} packages from PyPI...")
    
    try:
        # PyPI RSS feed for newest packages
        url = "https://pypi.org/rss/updates.xml"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        # Parse RSS to extract package names
        import xml.etree.ElementTree as ET
        root = ET.fromstring(response.content)
        
        packages = []
        for item in root.findall('.//item')[:limit]:
            title = item.find('title')
            if title is not None and title.text:
                # Title format is usually "package_name version"
                package_name = title.text.split()[0]
                packages.append(package_name)
        
        logging.info(f"Found {len(packages)} packages")
        return packages[:limit]
        
    except Exception as e:
        logging.error(f"Failed to fetch packages from PyPI RSS: {e}")
        
        # Fallback: Use PyPI JSON API to get popular packages
        try:
            logging.info("Falling back to PyPI JSON API...")
            # This doesn't give us the newest, but gives us packages to scan
            url = "https://pypi.org/simple/"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Parse simple API HTML
            import re
            packages = re.findall(r'<a href="[^"]*">([^<]+)</a>', response.text)
            packages = [p.strip() for p in packages if p.strip()]
            
            # Take a sample since we can't get "newest"
            import random
            packages = random.sample(packages, min(limit, len(packages)))
            
            logging.info(f"Fallback: Selected {len(packages)} random packages")
            return packages
            
        except Exception as e2:
            logging.error(f"Fallback also failed: {e2}")
            return []


def scan_package(package_name: str, move_dir: Path, cli_path: Path, timeout: int = 300) -> dict:
    """
    Scan a single PyPI package with malwi.
    
    Args:
        package_name: Name of the PyPI package
        move_dir: Directory to move suspicious findings to
        cli_path: Path to the malwi CLI
        
    Returns:
        Dictionary with scan results
    """
    try:
        # Construct the malwi command
        cmd = [
            str(cli_path),
            "pypi", 
            package_name,
            "--move", str(move_dir),
            "--quiet"  # Reduce output noise
        ]
        
        # Run the scan
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        return {
            "package": package_name,
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "suspicious": "👹" in result.stdout or "malicious" in result.stdout.lower()
        }
        
    except subprocess.TimeoutExpired:
        return {
            "package": package_name,
            "success": False,
            "error": "Timeout",
            "suspicious": False
        }
    except Exception as e:
        return {
            "package": package_name,
            "success": False,
            "error": str(e),
            "suspicious": False
        }


def main():
    """Main triage function."""
    parser = argparse.ArgumentParser(
        description="Triage PyPI packages by scanning newest packages for suspicious content"
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=100,
        help="Number of newest packages to scan (default: 100)"
    )
    parser.add_argument(
        "--move-dir", "-m",
        type=Path,
        default="../malwi-samples/python/suspicious",
        help="Directory to move suspicious findings to (default: ../malwi-samples/python/suspicious)"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=300,
        help="Timeout per package scan in seconds (default: 300)"
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Show packages that would be scanned without actually scanning"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print("🔍 PyPI Package Triage Utility")
    print("=" * 50)
    print(f"📊 Configuration:")
    print(f"   • Packages to scan: {args.count}")
    print(f"   • Move directory: {args.move_dir}")
    print(f"   • Timeout per scan: {args.timeout}s")
    print(f"   • Dry run: {args.dry_run}")
    print("=" * 50)
    
    # Validate paths
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    cli_path = project_root / "cli"
    
    # Check if CLI exists
    if not cli_path.exists():
        print(f"❌ Error: malwi CLI not found at {cli_path}")
        print("Make sure you're running this from the malwi project root")
        return 1
    
    # Set up move directory
    move_dir = args.move_dir.resolve()
    if not move_dir.parent.parent.exists():
        print(f"❌ Error: malwi-samples directory not found at {move_dir.parent.parent}")
        print("Please ensure malwi-samples is cloned in the parent directory")
        return 1
    
    # Create suspicious directory if it doesn't exist
    move_dir.mkdir(parents=True, exist_ok=True)
    print(f"📁 Suspicious findings will be saved to: {move_dir}")
    
    # Get newest packages
    packages = get_newest_pypi_packages(args.count)
    if not packages:
        print("❌ Failed to fetch packages from PyPI")
        return 1
    
    print(f"📦 Found {len(packages)} packages to process")
    
    # Handle dry run
    if args.dry_run:
        print("\n🔍 Packages that would be scanned:")
        for i, package in enumerate(packages, 1):
            print(f"  {i:3d}. {package}")
        print(f"\nDry run complete. Would scan {len(packages)} packages.")
        return 0
    
    print(f"📦 Starting triage of {len(packages)} packages...")
    print()
    
    # Scan packages with progress bar
    results = []
    suspicious_count = 0
    failed_count = 0
    
    with tqdm(packages, desc="🔍 Scanning packages", unit="pkg") as pbar:
        for package_name in pbar:
            pbar.set_postfix_str(f"Scanning {package_name[:20]}...")
            
            # Update scan_package call to use timeout from args
            result = scan_package(package_name, move_dir, cli_path, timeout=args.timeout)
            results.append(result)
            
            if result.get("suspicious", False):
                suspicious_count += 1
                pbar.set_postfix_str(f"👹 {package_name} - SUSPICIOUS!")
                # Brief pause to show the suspicious finding
                time.sleep(0.5)
            elif not result.get("success", False):
                failed_count += 1
                pbar.set_postfix_str(f"❌ {package_name} - Failed")
            else:
                pbar.set_postfix_str(f"🟢 {package_name} - Clean")
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Triage Summary")
    print("=" * 50)
    print(f"Total packages scanned: {len(packages)}")
    print(f"Suspicious packages found: {suspicious_count}")
    print(f"Failed scans: {failed_count}")
    print(f"Clean packages: {len(packages) - suspicious_count - failed_count}")
    
    # List suspicious packages
    suspicious_packages = [r for r in results if r.get("suspicious", False)]
    if suspicious_packages:
        print(f"\n👹 Suspicious packages ({len(suspicious_packages)}):")
        for result in suspicious_packages:
            print(f"  - {result['package']}")
    
    # List failed packages
    failed_packages = [r for r in results if not r.get("success", False) and not r.get("suspicious", False)]
    if failed_packages:
        print(f"\n❌ Failed scans ({len(failed_packages)}):")
        for result in failed_packages[:10]:  # Show first 10
            error = result.get("error", "Unknown error")
            print(f"  - {result['package']}: {error}")
        if len(failed_packages) > 10:
            print(f"  ... and {len(failed_packages) - 10} more")
    
    print(f"\n📁 Suspicious findings saved to: {move_dir}")
    print("\n🎉 Triage complete!")
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n🛑 Triage interrupted by user")
        sys.exit(130)
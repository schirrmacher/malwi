#!/usr/bin/env python3
"""
Build helpers to exclude training files from the package.
"""
import os
import shutil
from pathlib import Path

# Files to exclude from the package (training-only files)
EXCLUDE_FILES = [
    "src/research/train_distilbert.py",
    "src/research/train_tokenizer.py", 
    "src/research/preprocess.py",
    "src/research/analyze_data.py",
    "src/research/download_data.py",
    "src/research/filter_data.py",
    "src/research/csv_writer.py",
]

def backup_training_files():
    """Move training files to backup location before build."""
    backup_dir = Path("_training_backup")
    backup_dir.mkdir(exist_ok=True)
    
    moved_files = []
    for file_path in EXCLUDE_FILES:
        src = Path(file_path)
        if src.exists():
            dst = backup_dir / src.name
            shutil.move(str(src), str(dst))
            moved_files.append((src, dst))
            print(f"Backed up: {src} -> {dst}")
    
    return moved_files

def restore_training_files(moved_files):
    """Restore training files after build."""
    for original_path, backup_path in moved_files:
        if backup_path.exists():
            shutil.move(str(backup_path), str(original_path))
            print(f"Restored: {backup_path} -> {original_path}")
    
    backup_dir = Path("_training_backup")
    if backup_dir.exists() and not list(backup_dir.iterdir()):
        backup_dir.rmdir()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == "backup":
            moved_files = backup_training_files()
            # Write the list to a file so we can restore later
            with open("_moved_files.txt", "w") as f:
                for orig, backup in moved_files:
                    f.write(f"{orig}|{backup}\n")
        elif sys.argv[1] == "restore":
            moved_files = []
            if Path("_moved_files.txt").exists():
                with open("_moved_files.txt") as f:
                    for line in f:
                        if line.strip():
                            orig, backup = line.strip().split("|")
                            moved_files.append((Path(orig), Path(backup)))
                restore_training_files(moved_files)
                os.unlink("_moved_files.txt")
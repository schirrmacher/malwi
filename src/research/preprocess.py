#!/usr/bin/env python3
"""
Data preprocessing script for malwi training pipeline.
Processes Python/JavaScript files to generate AST-based malwicode tokens in parallel.
"""

import argparse
import csv
import logging
import multiprocessing as mp
import tempfile
from pathlib import Path
from typing import List, Dict
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm

from research.ast_to_malwicode import ASTCompiler
from research.malwi_object import collect_files_by_extension


def process_file_chunk(chunk_data: Dict) -> Dict:
    """
    Process a chunk of files in a separate process.

    Args:
        chunk_data: Dictionary containing:
            - files: List of file paths to process
            - language: Language type (python/javascript)
            - chunk_id: Identifier for this chunk
            - temp_dir: Temporary directory for output

    Returns:
        Dictionary with processing results and output file path
    """
    files = chunk_data["files"]
    language = chunk_data["language"]
    chunk_id = chunk_data["chunk_id"]
    temp_dir = Path(chunk_data["temp_dir"])

    # Initialize compiler for this process
    try:
        compiler = ASTCompiler(language)
    except ValueError as e:
        return {
            "chunk_id": chunk_id,
            "success": False,
            "error": str(e),
            "processed_count": 0,
        }

    # Create temporary output file for this chunk
    chunk_output = temp_dir / f"chunk_{chunk_id}.csv"

    processed_count = 0

    try:
        with open(chunk_output, "w", encoding="utf-8", newline="") as f:
            # Use proper CSV writer to handle escaping
            writer = csv.writer(f)
            writer.writerow(["tokens", "hash", "language", "filepath"])

            for file_path in files:
                try:
                    code_objects = compiler.process_file(file_path)

                    for obj in code_objects:
                        # Write CSV row with proper escaping
                        writer.writerow(
                            [
                                obj.to_string(one_line=True),
                                obj.to_hash(),
                                obj.language,
                                str(obj.path),
                            ]
                        )

                    processed_count += 1

                except Exception as e:
                    logging.warning(
                        f"Failed to process {file_path} in chunk {chunk_id}: {e}"
                    )
                    continue

        return {
            "chunk_id": chunk_id,
            "success": True,
            "output_file": str(chunk_output),
            "processed_count": processed_count,
        }

    except Exception as e:
        return {
            "chunk_id": chunk_id,
            "success": False,
            "error": str(e),
            "processed_count": processed_count,
        }


def split_files_into_chunks(files: List[Path], num_chunks: int) -> List[List[Path]]:
    """Split files into approximately equal chunks for parallel processing."""
    if not files:
        return []

    chunk_size = len(files) // num_chunks
    remainder = len(files) % num_chunks

    chunks = []
    start = 0

    for i in range(num_chunks):
        # Add one extra file to the first 'remainder' chunks
        current_chunk_size = chunk_size + (1 if i < remainder else 0)
        end = start + current_chunk_size

        if start < len(files):
            chunks.append(files[start:end])

        start = end

    # Remove empty chunks
    chunks = [chunk for chunk in chunks if chunk]
    return chunks


def combine_csv_chunks(chunk_files: List[str], output_path: Path) -> int:
    """
    Combine multiple CSV chunk files into a single output file.

    Returns:
        Total number of rows processed
    """
    total_rows = 0

    with open(output_path, "w", encoding="utf-8") as output_file:
        # Write header
        output_file.write("tokens,hash,language,filepath\n")

        for chunk_file in chunk_files:
            if Path(chunk_file).exists():
                with open(chunk_file, "r", encoding="utf-8") as f:
                    # Skip header line
                    next(f, None)
                    for line in f:
                        output_file.write(line)
                        total_rows += 1

    return total_rows


def preprocess_data(
    input_path: Path,
    output_path: Path,
    extensions: List[str] = None,
    num_processes: int = None,
    chunk_size: int = 100,
    use_parallel: bool = True,
) -> None:
    """
    Preprocess source files to generate malwicode tokens.

    Args:
        input_path: Directory containing source files
        output_path: Path to save CSV output
        extensions: List of file extensions to process
        num_processes: Number of parallel processes
        chunk_size: Approximate files per chunk
        use_parallel: Whether to use parallel processing
    """
    if extensions is None:
        extensions = [".py"]

    # Collect files
    print(f"🔍 Collecting files from {input_path}...")
    accepted_files, skipped_files = collect_files_by_extension(
        input_path=input_path, accepted_extensions=extensions, silent=False
    )

    if not accepted_files:
        print(f"No files with extensions {extensions} found in {input_path}")
        return

    print(f"Found {len(accepted_files)} files to process")

    # Decide whether to use parallel processing
    if not use_parallel or len(accepted_files) <= 10:
        print("Using sequential processing...")
        _process_sequential(accepted_files, output_path)
    else:
        print("Using parallel processing...")
        _process_parallel(accepted_files, output_path, num_processes, chunk_size)


def _process_sequential(files: List[Path], output_path: Path) -> None:
    """Process files sequentially."""
    from research.csv_writer import CSVWriter

    # Create compilers
    compilers = {}
    if any(f.suffix == ".py" for f in files):
        compilers["python"] = ASTCompiler("python")
    if any(f.suffix == ".js" for f in files):
        compilers["javascript"] = ASTCompiler("javascript")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    csv_writer = CSVWriter(output_path)

    try:
        for file_path in tqdm(files, desc="Processing files", unit="file"):
            if file_path.suffix == ".py":
                compiler = compilers.get("python")
            elif file_path.suffix == ".js":
                compiler = compilers.get("javascript")
            else:
                continue

            if compiler:
                code_objects = compiler.process_file(file_path)
                csv_writer.write_code_objects(code_objects)

        csv_writer.close()
        print(f"✅ Output saved to: {output_path.resolve()}")

    except Exception as e:
        csv_writer.close()
        raise e


def _process_parallel(
    files: List[Path],
    output_path: Path,
    num_processes: int = None,
    chunk_size: int = 100,
) -> None:
    """Process files in parallel."""
    if num_processes is None:
        num_processes = mp.cpu_count()

    # Calculate chunks
    num_chunks = max(1, len(files) // chunk_size)
    num_chunks = min(num_chunks, num_processes * 2)  # Don't create too many chunks

    print(f"Using {num_processes} processes with {num_chunks} chunks")

    # Group files by language
    files_by_language = {}
    for file_path in files:
        if file_path.suffix == ".py":
            lang = "python"
        elif file_path.suffix == ".js":
            lang = "javascript"
        else:
            continue

        if lang not in files_by_language:
            files_by_language[lang] = []
        files_by_language[lang].append(file_path)

    # Create temporary directory for chunk outputs
    with tempfile.TemporaryDirectory() as temp_dir:
        chunk_tasks = []
        chunk_id = 0

        # Create chunk tasks for each language
        for language, lang_files in files_by_language.items():
            file_chunks = split_files_into_chunks(lang_files, num_chunks)

            for chunk_files in file_chunks:
                if chunk_files:
                    chunk_tasks.append(
                        {
                            "files": chunk_files,
                            "language": language,
                            "chunk_id": chunk_id,
                            "temp_dir": temp_dir,
                        }
                    )
                    chunk_id += 1

        if not chunk_tasks:
            print("No valid files to process")
            return

        print(f"Created {len(chunk_tasks)} processing tasks")

        # Process chunks in parallel
        chunk_results = []

        with ProcessPoolExecutor(max_workers=num_processes) as executor:
            # Submit all tasks
            future_to_chunk = {
                executor.submit(process_file_chunk, task): task["chunk_id"]
                for task in chunk_tasks
            }

            # Collect results with progress bar
            with tqdm(
                total=len(chunk_tasks), desc="Processing chunks", unit="chunk"
            ) as pbar:
                for future in as_completed(future_to_chunk):
                    result = future.result()
                    chunk_results.append(result)
                    pbar.update(1)

                    if result["success"]:
                        pbar.set_postfix(
                            processed=result["processed_count"],
                            chunk=result["chunk_id"],
                        )

        # Combine results
        print("📋 Combining chunk results...")
        successful_chunks = [r for r in chunk_results if r["success"]]
        failed_chunks = [r for r in chunk_results if not r["success"]]

        if failed_chunks:
            print(f"⚠️  {len(failed_chunks)} chunks failed")
            for failed in failed_chunks:
                logging.warning(
                    f"Chunk {failed['chunk_id']}: {failed.get('error', 'Unknown error')}"
                )

        if successful_chunks:
            chunk_files = [r["output_file"] for r in successful_chunks]
            output_path.parent.mkdir(parents=True, exist_ok=True)

            total_rows = combine_csv_chunks(chunk_files, output_path)
            total_processed = sum(r["processed_count"] for r in successful_chunks)

            print(f"✅ Successfully processed {total_processed} files")
            print(f"📊 Generated {total_rows} code objects")
            print(f"💾 Output saved to: {output_path.resolve()}")
        else:
            raise RuntimeError("All chunks failed - no output generated")


def main():
    """Main entry point for preprocessing script."""
    parser = argparse.ArgumentParser(
        description="Preprocess source files for malwi training pipeline"
    )
    parser.add_argument(
        "input_path", type=Path, help="Directory containing source files to process"
    )
    parser.add_argument("output_path", type=Path, help="Path to save CSV output file")
    parser.add_argument(
        "--extensions",
        nargs="+",
        default=[".py"],
        help="File extensions to process (default: .py)",
    )
    parser.add_argument(
        "--num-processes",
        type=int,
        default=None,
        help="Number of parallel processes (default: CPU count)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=100,
        help="Approximate files per chunk (default: 100)",
    )
    parser.add_argument(
        "--no-parallel", action="store_true", help="Disable parallel processing"
    )

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(level=logging.WARNING)

    preprocess_data(
        input_path=args.input_path,
        output_path=args.output_path,
        extensions=args.extensions,
        num_processes=args.num_processes,
        chunk_size=args.chunk_size,
        use_parallel=not args.no_parallel,
    )


if __name__ == "__main__":
    main()

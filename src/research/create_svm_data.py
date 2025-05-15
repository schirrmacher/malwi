import os
import subprocess
import json
import argparse
import csv


def run_analysis_on_folder(folder_path):
    """
    Runs the analysis command on a given folder and extracts the JSON output.
    """
    command = ["uv", "run", "python", "-m", "src.cli.entry", folder_path, "-f", "json"]
    # This initial print indicates the start of processing for this folder
    print(f"INFO: Processing folder: {folder_path}")
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = process.communicate(timeout=300)  # 5-minute timeout

        if process.returncode == 0:
            try:
                output_json = json.loads(stdout)
                if all(
                    k in output_json
                    for k in [
                        "format",
                        "files_count",
                        "entities_count",
                        "malicious_percentage",
                    ]
                ):
                    extracted_data = {
                        "folder": folder_path,
                        "format": output_json.get("format"),
                        "files_count": output_json.get("files_count"),
                        "entities_count": output_json.get("entities_count"),
                        "malicious_percentage": output_json.get("malicious_percentage"),
                        "error": None,
                    }
                    # Detailed success log (optional, can be removed if too verbose with the new one-liner)
                    # print(f"DEBUG: Successfully extracted data for {folder_path}")
                    return extracted_data
                else:
                    missing_keys = [
                        k
                        for k in [
                            "format",
                            "files_count",
                            "entities_count",
                            "malicious_percentage",
                        ]
                        if k not in output_json
                    ]
                    print(
                        f"ERROR_DETAIL: Key(s) {missing_keys} not found in JSON output for {folder_path}. Output: {stdout[:200]}..."
                    )
                    return {
                        "folder": folder_path,
                        "error": f"MissingKeyError: {missing_keys}",
                        "raw_output": stdout,
                    }

            except json.JSONDecodeError as e:
                print(
                    f"ERROR_DETAIL: Could not decode JSON from output for {folder_path}: {e}. Output: {stdout[:200]}..."
                )
                return {
                    "folder": folder_path,
                    "error": f"JSONDecodeError: {e}",
                    "raw_output": stdout,
                }
        else:
            print(
                f"ERROR_DETAIL: Command failed for {folder_path} with return code {process.returncode}. Stderr: {stderr[:200]}..."
            )
            return {
                "folder": folder_path,
                "error": f"Command failed with code {process.returncode}",
                "stderr": stderr,
            }

    except subprocess.TimeoutExpired:
        print(f"ERROR_DETAIL: Command timed out for folder: {folder_path}")
        return {"folder": folder_path, "error": "TimeoutExpired"}
    except Exception as e:
        print(
            f"ERROR_DETAIL: An unexpected error occurred while processing {folder_path}: {e}"
        )
        return {"folder": folder_path, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="Run AI training analysis on repository folders and save results to CSV."
    )
    parser.add_argument(
        "--benign-dir",
        type=str,
        default=os.path.join(".repo_cache", "benign_repos"),
        help="Path to the directory containing benign repositories. Default: .repo_cache/benign_repos",
    )
    parser.add_argument(
        "--malicious-dir",
        type=str,
        default=os.path.join(".repo_cache", "malicious_repos", "pypi_malregistry"),
        help="Path to the directory containing malicious repositories. Default: .repo_cache/malicious_repos/pypi_malregistry",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        default="analysis_results.csv",
        help="File path to save the CSV results. Default: analysis_results.csv",
    )
    parser.add_argument(
        "--save-results",
        action="store_true",
        help="Save the results to the specified CSV output file.",
    )

    args = parser.parse_args()

    target_folders_info = []
    if os.path.isdir(args.benign_dir):
        target_folders_info.append({"path": args.benign_dir, "type": "benign"})
    else:
        print(f"WARNING: Benign directory not found: {args.benign_dir}. Skipping.")

    if os.path.isdir(args.malicious_dir):
        target_folders_info.append({"path": args.malicious_dir, "type": "malicious"})
    else:
        print(
            f"WARNING: Malicious directory not found: {args.malicious_dir}. Skipping."
        )

    if not target_folders_info:
        print(
            "ERROR: No valid benign or malicious directories provided or found. Exiting."
        )
        return

    all_results = []

    for folder_info in target_folders_info:
        current_target_path = folder_info["path"]
        repo_type = folder_info["type"]

        print(
            f"\nScanning '{repo_type}' repositories in: {current_target_path}\n--------------------------------------------------"
        )

        for item_name in os.listdir(current_target_path):
            item_path = os.path.join(current_target_path, item_name)
            if os.path.isdir(item_path):
                result = run_analysis_on_folder(item_path)
                if result:
                    result["type"] = repo_type  # This is the 'label'
                    all_results.append(result)

                    # One-line summary print after each scan
                    if result.get("error"):
                        error_summary = result["error"]
                        if isinstance(
                            error_summary, list
                        ):  # Handle cases like MissingKeyError
                            error_summary = ", ".join(str(e) for e in error_summary)
                        elif (
                            len(str(error_summary)) > 70
                        ):  # Truncate long error strings
                            error_summary = str(error_summary)[:67] + "..."
                        print(
                            f"SCAN_RESULT: FAILED '{os.path.basename(item_path)}' (Type: {repo_type}) - Error: {error_summary}"
                        )
                    else:
                        print(
                            f"SCAN_RESULT: OK '{os.path.basename(item_path)}' (Type: {repo_type}) - Files: {result.get('files_count', 'N/A')}, Entities: {result.get('entities_count', 'N/A')}, Malicious%: {result.get('malicious_percentage', 'N/A')}"
                        )
            else:
                # This print is for non-directory items, not directly related to scan results
                # print(f"INFO: Skipping non-directory item: {item_path}")
                pass

    print("\n\n--- Summary of All Results ---")
    if not all_results:
        print("No repositories were processed or no results were obtained.")
        return

    successful_analyses = 0
    failed_analyses = 0

    # Detailed summary loop (remains unchanged)
    for result in all_results:
        if result.get("error"):
            failed_analyses += 1
            print(f"\nFolder: {result['folder']} (Type: {result.get('type', 'N/A')})")
            print(f"  Status: FAILED")
            print(f"  Error: {result['error']}")
            if "stderr" in result:
                print(f"  Stderr: {result['stderr'][:500]}...")
            if "raw_output" in result:
                print(f"  Raw Output: {result['raw_output'][:500]}...")
        else:
            successful_analyses += 1
            print(f"\nFolder: {result['folder']} (Type: {result.get('type', 'N/A')})")
            print(f"  Format: {result['format']}")
            print(f"  Files Count: {result['files_count']}")
            print(f"  Entities Count: {result['entities_count']}")
            print(f"  Malicious Percentage: {result['malicious_percentage']}")

    print("\n--- Overall Statistics ---")
    print(f"Total repositories processed: {len(all_results)}")
    print(f"Successful analyses: {successful_analyses}")
    print(f"Failed analyses: {failed_analyses}")

    if args.save_results and all_results:
        successful_results_for_csv = [
            res for res in all_results if not res.get("error")
        ]
        if successful_results_for_csv:
            csv_columns = [
                "files_count",
                "entities_count",
                "malicious_percentage",
                "label",
            ]
            try:
                with open(args.output_file, "w", newline="") as csvfile:
                    writer = csv.DictWriter(
                        csvfile, fieldnames=csv_columns, extrasaction="ignore"
                    )
                    writer.writeheader()
                    for data in successful_results_for_csv:
                        row_data = {
                            "files_count": data.get("files_count"),
                            "entities_count": data.get("entities_count"),
                            "malicious_percentage": data.get("malicious_percentage"),
                            "label": data.get("type"),
                        }
                        writer.writerow(row_data)
                print(f"\nSuccessfully analyzed results saved to {args.output_file}")
            except IOError as e:
                print(f"\nERROR: Could not save CSV results to {args.output_file}: {e}")
            except Exception as e:
                print(f"\nERROR: An unexpected error occurred while writing CSV: {e}")
        else:
            print("\nNo successful analyses to save to CSV.")
    elif args.save_results and not all_results:
        print("\nNo results to save.")


if __name__ == "__main__":
    main()

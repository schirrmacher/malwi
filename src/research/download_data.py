import os
import subprocess
import logging
from urllib.parse import urlparse
import argparse
import shutil
import tarfile
import stat

BENIGN_REPO_URLS = [
    "https://github.com/pallets/flask.git",
    "https://github.com/aws/serverless-application-model.git",
    "https://github.com/psf/requests.git",
    "https://github.com/aws/aws-cli.git",
    "https://github.com/numpy/numpy.git",
    "https://github.com/pandas-dev/pandas.git",
    "https://github.com/scipy/scipy.git",
    "https://github.com/pytorch/pytorch.git",
    "https://github.com/tensorflow/tensorflow.git",
    "https://github.com/huggingface/transformers.git",
    "https://github.com/pyca/cryptography.git",
    "https://github.com/urllib3/urllib3.git",
    "https://github.com/google/python-fire",
    "https://github.com/googleapis/google-api-python-client",
    "https://github.com/python/cpython.git",
    "https://github.com/eliben/pycparser.git",
    "https://github.com/aio-libs/aiohttp.git",
    "https://github.com/fastapi/fastapi.git",
    "https://github.com/boto/boto3.git",
    "https://github.com/boto/botocore.git",
    "https://github.com/pypa/setuptools.git",
    "https://github.com/aws/deep-learning-containers.git",
    "https://github.com/aws/aws-sam-cli.git",
]
MALICIOUS_REPO_URL = "https://github.com/lxyeternal/pypi_malregistry.git"

REPO_CACHE_DIR = ".repo_cache"
BENIGN_REPOS_CACHE_PATH = os.path.join(REPO_CACHE_DIR, "benign_repos")
MALICIOUS_REPOS_CACHE_PATH = os.path.join(REPO_CACHE_DIR, "malicious_repos")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(module)s.%(funcName)s] %(message)s",
    handlers=[logging.StreamHandler()],
)


def make_writable_recursive(path_to_make_writable):
    logging.debug(f"Making {path_to_make_writable} owner-writable.")
    try:
        if os.path.isdir(path_to_make_writable):
            for root, dirs, files in os.walk(path_to_make_writable, topdown=False):
                for name in files:
                    filepath = os.path.join(root, name)
                    try:
                        current_mode = os.stat(filepath).st_mode
                        os.chmod(filepath, current_mode | stat.S_IWUSR)
                    except Exception as e:
                        logging.debug(
                            f"Could not make file {filepath} owner-writable: {e}"
                        )
                for name in dirs:
                    dirpath = os.path.join(root, name)
                    try:
                        current_mode = os.stat(dirpath).st_mode
                        os.chmod(dirpath, current_mode | stat.S_IWUSR | stat.S_IXUSR)
                    except Exception as e:
                        logging.debug(
                            f"Could not make dir {dirpath} owner-writable: {e}"
                        )
            current_mode = os.stat(path_to_make_writable).st_mode
            os.chmod(path_to_make_writable, current_mode | stat.S_IWUSR | stat.S_IXUSR)
        elif os.path.isfile(path_to_make_writable):
            current_mode = os.stat(path_to_make_writable).st_mode
            os.chmod(path_to_make_writable, current_mode | stat.S_IWUSR)
    except Exception as e:
        logging.warning(
            f"Error in make_writable_recursive for {path_to_make_writable}: {e}"
        )


def make_readonly(path):
    logging.debug(f"Setting group/other read-only permissions for {path}")
    perms_file = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
    perms_dir = stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
    try:
        if os.path.isdir(path):
            try:
                current_mode = os.stat(path).st_mode
                os.chmod(path, current_mode | stat.S_IWUSR | stat.S_IXUSR)
            except Exception:
                pass
            for root, dirs, files in os.walk(path, topdown=False):
                for f_name in files:
                    try:
                        os.chmod(os.path.join(root, f_name), perms_file)
                    except Exception:
                        pass
                for d_name in dirs:
                    try:
                        os.chmod(os.path.join(root, d_name), perms_dir)
                    except Exception:
                        pass
            os.chmod(path, perms_dir)
        elif os.path.isfile(path):
            os.chmod(path, perms_file)
    except Exception as e:
        logging.debug(
            f"Could not set group/other read-only permissions for {path}: {e}"
        )


def get_repo_name_from_url(url):
    try:
        path_part = urlparse(url).path
        repo_name = path_part.strip("/").replace(".git", "")
        return os.path.basename(repo_name)
    except Exception:
        return os.path.basename(url).replace(".git", "")


def run_command(command, working_dir=None, repo_name=""):
    logging.debug(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            cwd=working_dir,
            errors="ignore",
        )
        if result.stderr and not any(
            msg in result.stderr
            for msg in ["Cloning into", "Receiving objects", "Resolving deltas"]
        ):
            logging.debug(f"[{repo_name}] Command stderr: {result.stderr.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(
            f"[{repo_name}] Command failed: {' '.join(command)} (rc={e.returncode})"
        )
        if e.stderr:
            logging.error(f"[{repo_name}] Stderr: {e.stderr.strip()}")
        return False
    except Exception as e:
        logging.error(f"[{repo_name}] Error running command {' '.join(command)}: {e}")
        return False


def get_or_clone_repo(repo_url, target_cache_subdir):
    repo_name = get_repo_name_from_url(repo_url)
    repo_path = os.path.join(target_cache_subdir, repo_name)
    os.makedirs(target_cache_subdir, exist_ok=True)

    if os.path.exists(repo_path):
        logging.info(f"Using cached repository {repo_name} from {repo_path}")
    else:
        logging.info(f"Cloning {repo_name} from {repo_url} into {repo_path}")
        if not run_command(
            ["git", "clone", "--depth", "1", repo_url, repo_path], repo_name=repo_name
        ):
            logging.error(f"Failed to clone {repo_name}.")
            if os.path.exists(repo_path):
                try:
                    make_writable_recursive(repo_path)
                    shutil.rmtree(repo_path)
                except Exception as e_rm:
                    logging.warning(
                        f"Could not clean up partial clone {repo_path}: {e_rm}"
                    )
            return None
        make_readonly(repo_path)
    return repo_path


def ensure_writable_for_operation(path_to_check):
    try:
        current_mode = os.stat(path_to_check).st_mode
        if not (current_mode & stat.S_IWUSR):
            new_mode = current_mode | stat.S_IWUSR
            if os.path.isdir(path_to_check) and not (current_mode & stat.S_IXUSR):
                new_mode |= stat.S_IXUSR
            os.chmod(path_to_check, new_mode)
        return True
    except Exception as e:
        logging.debug(f"Could not ensure {path_to_check} owner-writable: {e}")
        if not os.access(path_to_check, os.W_OK):
            logging.warning(
                f"Path {path_to_check} not writable & could not be made owner-writable."
            )
            return False
        return True


def unpack_tar_gz_recursively(directory_to_scan):
    extracted_package_roots = []
    for root, _, files in os.walk(directory_to_scan, topdown=True):
        if not ensure_writable_for_operation(root):
            logging.warning(
                f"Cannot make {root} writable, skipping unpacking in this directory."
            )
            continue
        for filename in list(files):
            if filename.endswith(".tar.gz"):
                filepath = os.path.join(root, filename)
                logging.debug(f"Attempting to unpack {filepath}")
                if not ensure_writable_for_operation(filepath):
                    logging.warning(
                        f"Cannot make archive {filepath} writable for potential deletion, skipping."
                    )
                    continue

                extract_path_name = filename[: -len(".tar.gz")]
                extract_full_path = os.path.join(root, extract_path_name)

                try:
                    if not os.path.exists(extract_full_path):
                        if ensure_writable_for_operation(root):
                            os.makedirs(extract_full_path, exist_ok=True)
                        else:
                            logging.warning(
                                f"Parent directory {root} not writable to create {extract_full_path}, skipping."
                            )
                            continue
                    elif not os.path.isdir(extract_full_path):
                        logging.warning(
                            f"Extraction path {extract_full_path} exists but is not a directory, skipping."
                        )
                        continue

                    if not ensure_writable_for_operation(extract_full_path):
                        logging.warning(
                            f"Extraction target {extract_full_path} not writable, skipping."
                        )
                        continue

                    with tarfile.open(filepath, "r:gz") as tar:
                        tar.extractall(path=extract_full_path)
                    logging.debug(
                        f"Successfully unpacked {filepath} to {extract_full_path}"
                    )
                    extracted_package_roots.append(extract_full_path)
                    make_readonly(extract_full_path)

                    try:
                        os.remove(filepath)
                        logging.debug(f"Successfully removed archive {filepath}")
                    except OSError as e_remove:
                        logging.error(
                            f"Failed to remove archive {filepath} after extraction: {e_remove}"
                        )

                except tarfile.ReadError as e_tar:
                    # Log as DEBUG: these are expected for some files in this dataset
                    logging.debug(
                        f"Skipping file {filepath} as it's not a valid tar.gz file or is corrupted: {e_tar}"
                    )
                except Exception as e_unpack:
                    logging.error(f"Failed to unpack or process {filepath}: {e_unpack}")
    return list(set(extracted_package_roots))


def process_benign_repositories(repo_urls):
    logging.info("Processing benign repositories...")
    processed_paths = []
    for repo_url in repo_urls:
        repo_name = get_repo_name_from_url(repo_url)
        try:
            cloned_repo_path = get_or_clone_repo(repo_url, BENIGN_REPOS_CACHE_PATH)
            if not cloned_repo_path:
                continue
            processed_paths.append(cloned_repo_path)
            logging.info(f"Processing benign: {repo_name}")
            # Placeholder for actual processing logic
        except Exception as e:
            logging.error(f"Error processing benign repo {repo_name}: {e}")
    return processed_paths


def process_malicious_repository(repo_url):
    logging.info("Processing malicious repository...")
    repo_name = get_repo_name_from_url(repo_url)
    processed_package_paths = []
    try:
        cloned_mal_repo_path = get_or_clone_repo(repo_url, MALICIOUS_REPOS_CACHE_PATH)
        if not cloned_mal_repo_path:
            return []

        make_writable_recursive(cloned_mal_repo_path)
        logging.info(f"Unpacking archives in malicious repo: {repo_name}")
        all_extracted_malicious_package_paths = unpack_tar_gz_recursively(
            cloned_mal_repo_path
        )
        make_readonly(cloned_mal_repo_path)

        if not all_extracted_malicious_package_paths:
            logging.warning(
                f"No .tar.gz packages extracted from {cloned_mal_repo_path}."
            )
        else:
            logging.info(
                f"Found {len(all_extracted_malicious_package_paths)} malicious packages for processing."
            )
            for package_path in all_extracted_malicious_package_paths:
                descriptive_package_name = f"{repo_name}_{os.path.relpath(package_path, cloned_mal_repo_path).replace(os.sep, '_')}"
                logging.info(
                    f"Processing malicious package: {descriptive_package_name}"
                )
                # Placeholder for actual processing logic
                processed_package_paths.append(package_path)
    except Exception as e:
        logging.error(f"Error processing malicious repo {repo_name}: {e}")
    return processed_package_paths


def main():
    parser = argparse.ArgumentParser(
        description="Clone/use cached repositories and process them."
    )
    parser.add_argument(
        "--type",
        type=str,
        choices=["benign", "malicious", "all"],
        default="all",
        help="Type of dataset to process (default: all)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    args, unknown = parser.parse_known_args()
    if unknown:
        logging.debug(f"Ignoring unknown arguments: {unknown}")

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.INFO)

    logging.info(
        f"Initializing script, using cache directory: {os.path.abspath(REPO_CACHE_DIR)}"
    )
    os.makedirs(BENIGN_REPOS_CACHE_PATH, exist_ok=True)
    os.makedirs(MALICIOUS_REPOS_CACHE_PATH, exist_ok=True)

    if args.type in ["benign", "all"]:
        process_benign_repositories(BENIGN_REPO_URLS)

    if args.type in ["malicious", "all"]:
        process_malicious_repository(MALICIOUS_REPO_URL)

    logging.info("Script execution finished.")


if __name__ == "__main__":
    main()

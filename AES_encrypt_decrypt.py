#!usr/bin/python3

from os import urandom
import binascii
from Crypto.Cipher import AES

# AES encryption, with CBF mode
# AES KEY: 32 bytes
# AES IV: 16 bytes


def aes_generate_key_iv():
    AES_KEY = urandom(32)
    AES_IV = urandom(16)

    print("AES_KEY:",binascii.b2a_hex(AES_KEY).decode())
    print("AES_IV:",binascii.b2a_hex(AES_IV).decode())

def aes_encrypt(plaintext,AES_KEY,AES_IV):
    AES_KEY    = binascii.a2b_hex(AES_KEY) # Convert hex string to binary
    AES_IV     = binascii.a2b_hex(AES_IV) # Convert hex string to binary
    AES_Cipher = AES.new(AES_KEY,AES.MODE_CFB,AES_IV) # create a cipher object
    ciphertext = AES_Cipher.encrypt(plaintext.encode())
    print("ciphertext :",binascii.b2a_hex(ciphertext).decode())

def aes_decrypt(ciphertext,AES_KEY,AES_IV):
    AES_KEY = binascii.a2b_hex(AES_KEY) # convert hex string to binary
    AES_IV = binascii.a2b_hex(AES_IV) # convert hex string to binary
    AES_Cipher = AES.new(AES_KEY,AES.MODE_CFB,AES_IV) # create a cipher object
    ciphertext = binascii.a2b_hex(ciphertext) # convert hex string to binary
    plaintext = AES_Cipher.decrypt(ciphertext)
    print("plaintext: ",plaintext.decode())

# aes_generate_key_iv()
aes_encrypt("secret message to be encrypted","805f11b3c04841db3de9534fd156f09ea99198b49f0ec647375765dcddd3ec8f","8e81ef21c8b3cffd1ab979dcacd02b26")
aes_decrypt("7b0a030d9a088a6f7630e90b578e9e3f1f9905c74a43c9fb7300a100e6bb","805f11b3c04841db3de9534fd156f09ea99198b49f0ec647375765dcddd3ec8f","8e81ef21c8b3cffd1ab979dcacd02b26")


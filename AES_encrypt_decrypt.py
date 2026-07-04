#!usr/bin/python3

from os import urandom
import binascii

# AES encryption, with CBF mode
# AES KEY: 32 bytes
# AES IV: 16 bytes


def aes_generate_key_iv():
    AES_KEY = urandom(32)
    AES_IV = urandom(16)

    print("AES_KEY:",binascii.b2a_hex(AES_KEY).decode())
    print("AES_IV:",binascii.b2a_hex(AES_IV).decode())

aes_generate_key_iv()

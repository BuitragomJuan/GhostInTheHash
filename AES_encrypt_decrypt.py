#!usr/bin/python3

from os import urandom
import binascii
from Crypto.Cipher import AES
import argparse
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

def main(mode,plaintext,AES_KEY,AES_IV,ciphertext):
    if mode == "aes_generate_key_iv":
        aes_generate_key_iv()

    elif mode == "aes_encrypt":
        aes_encrypt(plaintext,AES_KEY,AES_IV)
    elif mode == "aes_decrypt":
        aes_decrypt(ciphertext,AES_KEY,AES_IV)
    else:
        print("Invalid mode typed")
        exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encryption and Decryptio using AES")
    parser.add_argument("-m","--mode",help="mode can only be: aes_generate_key_iv,aes_encrypt and aes_decrypt")
    parser.add_argument("-p","--plaintext",help="data to be encryptes")
    parser.add_argument("-c","--ciphertext",help="data to be decrypted")
    parser.add_argument("-k","--aes_key",help="AES_KEY of size 32 bytes in hexadecimal format")
    parser.add_argument("-i","--aes_iv",help="AES_IV of size 16 bytes in hevadecimal format")

    # get the value of this option
    args       = parser.parse_args()
    mode       = args.mode
    plaintext  = args.plaintext
    ciphertext = args.ciphertext
    AES_KEY    = args.aes_key
    AES_IV     = args.aes_iv

    main(mode=mode,plaintext=plaintext,AES_KEY=AES_KEY,AES_IV=AES_IV,ciphertext=ciphertext)
    exit(0)

#!usr/bin/python

from Crypto.PublicKey import RSA
import os,binascii
from Crypto.Cipher import PKCS1_OAEP
def RSA_KEY_generate(key_size):
    try:
        # generate RSA key of size key:size in bits
        key = RSA.generate(key_size)

        # get private key
        private_key = key.export_key(passphrase="Password_For_Private_Key",pkcs=8,protection="scryptAndAES128-CBC").decode()
        print(private_key)
        fp = open("/home/uitr/bash_EH/RSA_keys/private_key.pem","wt")
        fp.write(private_key)
        fp.close()

        # get public key
        public_key = key.publickey().export_key().decode()
        print(public_key)
        fp = open("/home/uitr/bash_EH/RSA_keys/public_key.pem","wt")
        fp.write(public_key)
        fp.close()

    except Exception as e:
        print("Error: ",e)
        exit(1)

# RSA_KEY_generate(2048)


def SESSION_KEY_ENCRYPT(public_key_file):
    try:
        session_key = os.urandom(32)
        print("session_key:",binascii.b2a_hex(session_key).decode())

        # get public key
        public_key = RSA.import_key(open(public_key_file).read())

        # construct rsa cipher object and encrypt the session key
        rsa_cipher = PKCS1_OAEP.new(public_key)
        encrypted_session_key = rsa_cipher.encrypt(session_key)
        print("encrypted_session_key:",binascii.b2a_hex(encrypted_session_key).decode())

    except Exception as e:
        print("Error:",e)
        exit(1)

#SESSION_KEY_ENCRYPT("/home/uitr/bash_EH/RSA_keys/public_key.pem")


def RSA_SESSION_KEY_DECRYPT(private_key_file):
    try:
        encrypted_session_key = "6a6620cee6d83ceef62a833a68022528cd5f7fd1dd95f162940d962fcb2064e058dc157438d42ace81018701090076252af36718ec0f6f49c97dcd0c7bb4e1d4701621553f295d7c16a46e5a1b60c9d061f9ec746e66d3596be1318443893d8bd1acc56e622d947fd340866121dec82f5440ec7d0a120614f771b955822b7219c74fb0eefb040c95cf5a6a2c4792414ba0d07e70547566e713059e3f1c401a8cf7dab7a48f2395bde768850f44d3c4e80b54822a18c65144824cfbd619f2eaca0c93c54ea984709d93970b6e8a2b6a9b0cc89f2a0467b7c1a4a9efcb47b38ede802964adc06de5184b3ea39321ef3c145b48b9d7fcd4dfa9f5db655bc268e2e7"
        encrypted_session_key = binascii.a2b_hex(encrypted_session_key.encode())


        # get private key
        private_key = RSA.import_key(open(private_key_file).read(),passphrase="Password_For_Private_Key")

        # construct rsa cipher object and decrypt the session key
        rsa_cipher = PKCS1_OAEP.new(private_key)
        session_key = rsa_cipher.decrypt(encrypted_session_key)
        print("decrypted_session_key:",binascii.b2a_hex(session_key).decode())

    except Exception as e:
        print("Error:",e)
        exit(1)


RSA_SESSION_KEY_DECRYPT("/home/uitr/bash_EH/RSA_keys/private_key.pem")

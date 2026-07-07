#!usr/bin/python

from Crypto.PublicKey import RSA

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

RSA_KEY_generate(2048)

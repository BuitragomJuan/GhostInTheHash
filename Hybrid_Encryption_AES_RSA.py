#!usr/bin/python

from Crypto.PublicKey import RSA

# generate RSA key of size 2048 bits
key = RSA.generate(2048)

# get private key
private_key = key.export_key().decode()
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

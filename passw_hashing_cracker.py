#!usr/bin/python3
import binascii
import hashlib

password = 'password1234+'
utf_password = password.encode("UTF-8")

# encode the password
base64_password = binascii.b2a_base64(utf_password)
hex_password = binascii.b2a_hex(utf_password)
print(base64_password.decode("UTF-8").strip("\n"))
print(hex_password.decode("UTF-8").strip("\n"))

# hash the password
hashing_algorithms = ['md5','sha1','sha224','sha3_224','sha256','sha3_256','sha512','sha3_512']
for hashing_algorithm in hashing_algorithms:
    password_hash = hashlib.new(hashing_algorithm,utf_password).hexdigest()
    print(hashing_algorithm," "*(15-len(hashing_algorithm)),password_hash,'hash_length_in_bytes:',int(len(password_hash)/2))

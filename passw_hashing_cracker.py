#!usr/bin/python3
import binascii
import hashlib
from passlib.hash import mysql323, mysql41, mssql2000, mssql2005, postgres_md5, oracle10, oracle11
from passlib.hash import lmhash,nthash,msdcc,msdcc2

R ="\033[1;31m";
Y ="\033[1;33m";
C ="\033[1;36m";
W ="\033[0m";

password = 'password1234+'
utf_password = password.encode("UTF-8")
username    = 'administrator'
utf_username    = username.encode("UTF-8")
# encode the password
base64_password = binascii.b2a_base64(utf_password)
hex_password = binascii.b2a_hex(utf_password)
print("base64: ",base64_password.decode("UTF-8").strip("\n"))
print("hex: ",hex_password.decode("UTF-8").strip("\n"))
print("\n")

# hash the password using native functions
hashing_algorithms = ['md5','sha1','sha224','sha3_224','sha256','sha3_256','sha512','sha3_512']
for hashing_algorithm in hashing_algorithms:
    password_hash = hashlib.new(hashing_algorithm,utf_password).hexdigest()
    print(hashing_algorithm," "*(15-len(hashing_algorithm)),password_hash,'hash_length_in_bytes:',int(len(password_hash)/2))
print("\n")

# sql hashing functions
print("mysql323     :",C,mysql323.hash(utf_password),W)
print("mysql41      :",C,mysql41.hash(utf_password),W)
print("mssql2000    :",C,mssql2000.hash(utf_password),W)
print("mssql2005    :",C,mssql2005.hash(utf_password),W)
print("postgres_md5 :",C,postgres_md5.hash(utf_password, user=utf_username),W)
print("mysql323     :",C,oracle10.hash(utf_password,user=utf_username),W)
print("mysql323     :",C,oracle11.hash(utf_password),W)
print("\n")

# modern versions of windows have different accounts including NTLM and MSCASH
# NTLM (C/SYSTEM32/CONFIG/SAM) hashes are used for local accounts and MSCASH (C/SYSTEM32/CONFIG/SECURITY) hashes are used for domain accounts
print("Windows LM hash      :",C,lmhash.hash(utf_password),W)
print("Windows LM hash      :",C,nthash.hash(utf_password),W)
print("Windows LM hash      :",C,msdcc.hash(utf_password,user=utf_username),W)
print("Windows LM hash      :",C,msdcc2.hash(utf_password,user=utf_username),W)

#!usr/bin/python3
import binascii
import hashlib
from passlib.hash import mysql323, mysql41, mssql2000, mssql2005, postgres_md5, oracle10, oracle11
from passlib.hash import lmhash,nthash,msdcc,msdcc2
from passlib.hash import pbkdf2_sha256,pbkdf2_sha512,sha512_crypt,sha256_crypt,bcrypt
from os import urandom
import time
import argparse,threading,queue,sys
from passlib.context import CryptContext
R ="\033[1;31m";
Y ="\033[1;33m";
C ="\033[1;36m";
W ="\033[0m";

def password_hash(password):
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
    print("oracle10     :",C,oracle10.hash(utf_password,user=utf_username),W)
    print("oracle11     :",C,oracle11.hash(utf_password),W)
    print("\n")

    # modern versions of windows have different accounts including NTLM and MSCASH
    # NTLM (C/SYSTEM32/CONFIG/SAM) hashes are used for local accounts and MSCASH (C/SYSTEM32/CONFIG/SECURITY) hashes are used for domain accounts
    print("Windows LM hash      :",C,lmhash.hash(utf_password),W)
    print("Windows NT hash      :",C,nthash.hash(utf_password),W)
    print("Windows MSCCASH hash :",C,msdcc.hash(utf_password,user=utf_username),W)
    print("Windows MSCASH2 hash :",C,msdcc2.hash(utf_password,user=utf_username),W)

    # generate a random salt
    salt = urandom(32) # size is 32 bytes
    decoded_salt = binascii.b2a_base64(salt).decode().strip()
    decoded_salt = decoded_salt.replace("+",".").replace("=","")
    print("\nsalt :",decoded_salt)
    print("\n")

    T1 = time.time()
    print("pbkdf2 :",C,pbkdf2_sha256.hash(utf_password,rounds=100000,salt=salt),R,time.time() - T1,W,"seconds")
    T1 = time.time()
    print("pbkdf2 :",C,pbkdf2_sha512.hash(utf_password,rounds=100000,salt=salt),R,time.time() - T1,W,"seconds")

    sha512_crypt_salt = decoded_salt[:16]
    T1 = time.time()
    print("sha512_crypt :",C,sha512_crypt.hash(utf_password,rounds=8000,salt=sha512_crypt_salt),R,time.time() - T1,W,"seconds")
    T1 = time.time()
    print("sha256_crypt:",C,sha256_crypt.hash(utf_password,rounds=8000,salt=sha512_crypt_salt),R,time.time() - T1,W,"seconds")

    bsd_salt = decoded_salt[:22]
    bsd_salt = bsd_salt.replace(bsd_salt[21],".")
    T1 = time.time()
    print("bcrypt :",C,bcrypt.hash(utf_password,rounds=12,salt=bsd_salt),R,time.time() - T1,W,"seconds")

def password_crack(password_hash,hashing_algorithm,hashing_algorithms_1,hashing_algorithms_2,username_salt):
    global q
    while not q.empty():
        try:
            password = q.get()  ## Remove and return an item from the queue.
            if hashing_algorithm in hashing_algorithms_1:
                if hashlib.new(hashing_algorithm, password.encode("UTF-8")).hexdigest() == password_hash:
                    print("\nfound credentials:",C,password,W)
                    q.task_done() # Indicate that a formerlu enqueued task is complete
                    # We need to stop all the threads  once the good password is found
                    with q.mutex: q.queue.clear(); q.all_tasks_done.notify_all(); q.unfinished_tasks = 0
                    return
            elif hashing_Algorithm in hashing_algorithms_2:
                pwd_context = CryptContext(schemes = [hashing_algorithm],) # add hashing_algorithms to crypto context schemes
                try:
                    if pwd_context.verify(password,password_hash,hashing_algorithm) == True: # Compare the two hashes
                        print("\nfound credentials:",C,password,W)
                        q.task_done() # Indicate that a formerly enqueued task is complete
                        # we need to stop all the threads once the good password is found 
                        with q.mutex: q.queue.clear(); q.all_tasks_done-notify_all(); q.unfinished_tasks = 0
                        return
                except:
                    pass
            else: # hashing functions that require username as salt, like msdcc, postgresql and oracle
                pwd_context = CryptContext(schemes = [hashing_algorithm],) # add hasing_algorithms to crypto context scheme
                try: 
                    if pwd_context.verify(password, password_hash, hashing_algorithm,user=username_salt) == True:
                        print("\nfound credentials:",C,password,W)
                        q.task_done()
                        # we need to stop all the threads once the good password is found
                        with q.mutex: q.queue.clear(); q.all_tasks_done.notify_all(); q.unfinished_tasks = 0
                        return
                except:
                    pass
            q.task_done()   # Indicate that a formerly enqueued task is complete
        except :
            pass
q = queue.Queue() ##passwords will be stored in this queue
def main(mode,password,passwordhash,hashing_algorithm,n_threads,wordlist,username_salt):

    ## hashlib module to be used to crack hashes:
    hashing_algorithms_1 = ['md4','md5','sha1','sha224','sha3_224','sha_256','sha3_256','sha3_256','sha384','sha3_384','sha512','sha3_512']
    ## passlib module to be used to crack hashes:
    hashing_algorithms_2 = ['lmhash','nthash','pbkdf2_sha256','sha256_crypt','sha512_crypt','bcrypt','mysql323','mysql41','mssql2000','mssql2005','oracle11']
    ## password hashing functions tha require username as a salt
    hashing_algorithms_3 = ['msdcc','msdcc2','postgres_md5','oracle10']

    if mode == 'hashing':
        password_hash(password)

    elif mode == 'cracking':
        global q 
        try:
            # fill the queue with all the wordlist_items
            with open(wordlist) as wordlist_items:
                for wordlist_item in wordlist_items: q.put(wordlist_item.strip())
        except:
            print(R,"Error: dictionary file not found",W)
            sys.exit()
        if hashing_algorithm not in hashin_algorithms_1 and hashing_algorithm not in hashing_algorithms_2 and hashing_algorithm not in hashing_algorithms_3:
            print(R,"Error: invalid hashing algorithm",W)
            sys.exit()
        if hashing_algorithm in hashing_algorithms_3 and username_salt == None:
            print(R,"Error: hashing algorithm require a username as a salt",W)
            sys.exit()

        # start the threads
        for t in range(n_threads):
            # create a new thread
            worker = threading.Thread(target=password_crack, args=(passwordhash,hashing_algorithm,hashing_algorithms_1,hashing_algorithms_2,username_salt))
            worker.daemon = True # daemon thread means a thread that will end when the main thread ends
            worker.start()  # start the new thread
        else:
            print(R,"mode can be only hashing or cracking",W)
            sys.exit()


if __name__=="__main__":
    parser = argparse.ArgumentParser(description="password hash generator and cracker")
    parser.add_argument("-m", "--mode",                 help="hashing or cracking mode")
    parser.add_argument("-p", "--password",             help="password to be hashed")
    parser.add_argument("-s", "--passwordhash",         help="password hash to be cracked")
    parser.add_argument("-a", "--hashing_algorithm",    help="hashing algorithm to be used for cracking ['md4','md5','sha1','ripemd160','sha224','sha3_224','sha256',sha3_]")
    parser.add_argument("-w", "--wordlist",             help="Dictionary File to be used for password hash cracking")
    parser.add_argument("-t", "--num-threads",          help="Number of threads to use to bruteforce the login-page. DEfault is 1", default=1, type=int)
    parser.add_argument("-u", "--username_salt",        help="username to be used as a slat in hashing functions like mscache, postgreql and oracle")

    ## get the arguments
    args              = parser.parse_args()
    mode              = args.mode               ## get mode, hashing or cracking mode
    password          = args.password           ## get password to be hashed
    passwordhash      = args.passwordhash       ## get password hash to be cracked
    hashing_algorithm = args.hashing_algorithm  ## get hashing algorithm to be used for cracking
    wordlist          = args.wordlist           ## get wordlist to be used
    num_threads       = args.num_threads        ## number of threads in bruteforce
    username_salt     = args.username_salt      ## username to be used as a slat in hashing functions like mscache, psotgresql and oracle

    main(mode=mode,password=password,passwordhash=passwordhash,hashing_algorithm=hashing_algorithm,n_threads=num_threads,wordlist=wordlist,username_salt=username_salt)
    q.join() # Blocks until all items in the queue have been gotten and processed
    sys.exit()

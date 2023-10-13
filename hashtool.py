#Thanks to the teacher & class

import colorama
import pyfiglet
import hashlib
import os

os.system('cls')
banner = pyfiglet.figlet_format("Ark Ang3l hash Cracker", font="digital")
menu = '''
[1] Hash Type Detector
[2] Hash Generator
[3] Hash Cracker
[4] exit
'''
print((colorama.Fore.RED + banner + colorama.Fore.RESET))
print((colorama.Fore.GREEN + menu + colorama.Fore.RESET))

user_input = int(input(colorama.Fore.BLUE + "Enter your choice: " + colorama.Fore.RESET))

while user_input not in range(1, 4):
    os.system('cls')
    print((colorama.Fore.RED + banner + colorama.Fore.RESET))
    print((colorama.Fore.GREEN + menu + colorama.Fore.RESET))
    user_input = int(input(colorama.Fore.BLUE + "Enter your choice (between 1, 2, 3, 4): " + colorama.Fore.RESET))


def hash_type_detetor():
    hash = input(colorama.Fore.CYAN + 'please input your hash to decode: ' + colorama.Fore.RESET)

    digested_hash = len(hash) / 2

    md5 = hashlib.md5()
    md5 = md5.digest_size
    sha1 = hashlib.sha1()
    sha1 = sha1.digest_size
    sha224 = hashlib.sha224()
    sha224 = sha224.digest_size
    sha256 = hashlib.sha256()
    sha256 = sha256.digest_size
    sha384 = hashlib.sha384()
    sha384 = sha384.digest_size
    sha512 = hashlib.sha512()
    sha512 = sha512.digest_size
    sha3_384 = hashlib.sha3_384()
    sha3_384 = sha3_384.digest_size
    sha3_512 = hashlib.sha3_512()
    sha3_512 = sha3_512.digest_size
    sha3_256 = hashlib.sha3_256()
    sha3_256 = sha3_256.digest_size
    sha3_224 = hashlib.sha3_224()
    sha3_224 = sha3_224.digest_size
    blake2s = hashlib.blake2s()
    blake2s = blake2s.digest_size
    blake2b = hashlib.blake2b()
    blake2b = blake2b.digest_size

    if digested_hash == md5:
        print('digested hash is md5')
        hash_type = hashlib.md5()
        return hash_type
    elif digested_hash == sha1:
        print('digested hash is sha-1')
        hash_type = hashlib.sha1()
        return hash_type
    elif digested_hash == sha224:
        print('digested hash is sha-224')
        hash_type = hashlib.sha224()
        return hash_type
    elif digested_hash == sha256:
        print('digested hash is sha-256')
        hash_type = hashlib.sha256()
        return hash_type
    elif digested_hash == sha384:
        print('digested hash is sha-384')
        hash_type = hashlib.sha384()
        return hash_type
    elif digested_hash == sha512:
        print('digested hash is sha-512')
        hash_type = hashlib.sha512()
        return hash_type
    elif digested_hash == sha3_512:
        print('digested hash is sha3_512')
        hash_type = hashlib.sha3_512()
        return hash_type
    elif digested_hash == sha3_256:
        print('digested hash is sha3_256')
        hash_type = hashlib.sha3_256()
        return hash_type
    elif digested_hash == sha3_384:
        print('digested hash is sha3_384')
        hash_type = hashlib.sha3_384()
        return hash_type
    elif digested_hash == sha3_224:
        print('digested hash is sha3_224')
        hash_type = hashlib.sha3_224()
        return hash_type
    elif digested_hash == blake2s:
        print('digested hash is blake2s')
        hash_type = hashlib.blake2s()
        return hash_type
    elif digested_hash == blake2b:
        print('digested hash is blake2b')
        hash_type = hashlib.blake2b()
        return hash_type
    else:
        print('I don not know WHat this hash is :(')
        hash_type = None


def hash_generator():
    user_hash_kind = input(
        colorama.Fore.YELLOW + f'please select your hash type between=>\n(sha3_512, sha3_256, sha3_224, sha512, sha224, sha1, blake2s, blake2b, sha256, sha384, sha3_384, md5) : ' + colorama.Fore.RESET)
    user_text = input(colorama.Fore.LIGHTGREEN_EX + 'please input your text to hash : ' + colorama.Fore.RESET)
    if user_hash_kind == 'sha3_512':
        hash_type = hashlib.sha3_512()
        hash_type.update(user_text.encode())
        print(hash_type.hexdigest())
    elif user_hash_kind == 'sha3_256':
        hash_type = hashlib.sha3_256()
        hash_type.update(user_text.encode())
        print(hash_type.hexdigest())
    elif user_hash_kind == 'sha3_224':
        hash_type = hashlib.sha3_224()
        hash_type.update(user_text.encode())
        print(hash_type.hexdigest())
    elif user_hash_kind == 'sha512':
        hash_type = hashlib.sha512()
        hash_type.update(user_text.encode())
        print(hash_type.hexdigest())
    elif user_hash_kind == 'sha224':
        hash_type = hashlib.sha224()
        hash_type.update(user_text.encode())
        print(hash_type.hexdigest())
    elif user_hash_kind == 'sha1':
        hash_type = hashlib.sha1()
        hash_type.update(user_text.encode())
        print(hash_type.hexdigest())
    elif user_hash_kind == 'blake2s':
        hash_type = hashlib.blake2s()
        hash_type.update(user_text.encode())
        print(hash_type.hexdigest())
    elif user_hash_kind == 'blake2b':
        hash_type = hashlib.blake2b()
        hash_type.update(user_text.encode())
        print(hash_type.hexdigest())
    elif user_hash_kind == 'sha256':
        hash_type = hashlib.sha256()
        hash_type.update(user_text.encode())
        print(hash_type.hexdigest())
    elif user_hash_kind == 'sha384':
        hash_type = hashlib.sha384()
        hash_type.update(user_text.encode())
        print(hash_type.hexdigest())
    elif user_hash_kind == 'sha3_384':
        hash_type = hashlib.sha3_384()
        hash_type.update(user_text.encode())
        print(hash_type.hexdigest())
    elif user_hash_kind == 'md5':
        hash_type = hashlib.md5()
        hash_type.update(user_text.encode())
        print(hash_type.hexdigest())
    else:
        print('enter exactly hash type next time .')


def hash_cracker():
    wordlist = input(colorama.Fore.YELLOW + 'please input your wordlist path: ' + colorama.Fore.RESET)
    hash_to_crack = input(colorama.Fore.YELLOW + 'please input your hash to crack: ' + colorama.Fore.RESET)
    digested_hash = len(hash_to_crack) / 2

    md5 = hashlib.md5()
    md5 = md5.digest_size
    sha1 = hashlib.sha1()
    sha1 = sha1.digest_size
    sha224 = hashlib.sha224()
    sha224 = sha224.digest_size
    sha256 = hashlib.sha256()
    sha256 = sha256.digest_size
    sha384 = hashlib.sha384()
    sha384 = sha384.digest_size
    sha512 = hashlib.sha512()
    sha512 = sha512.digest_size
    sha3_384 = hashlib.sha3_384()
    sha3_384 = sha3_384.digest_size
    sha3_512 = hashlib.sha3_512()
    sha3_512 = sha3_512.digest_size
    sha3_256 = hashlib.sha3_256()
    sha3_256 = sha3_256.digest_size
    sha3_224 = hashlib.sha3_224()
    sha3_224 = sha3_224.digest_size
    blake2s = hashlib.blake2s()
    blake2s = blake2s.digest_size
    blake2b = hashlib.blake2b()
    blake2b = blake2b.digest_size

    if digested_hash == md5:
        global hash_type
        hash_type = hashlib.md5()

    elif digested_hash == sha1:

        hash_type = hashlib.sha1()

    elif digested_hash == sha224:

        hash_type = hashlib.sha224()

    elif digested_hash == sha256:

        hash_type = hashlib.sha256()

    elif digested_hash == sha384:

        hash_type = hashlib.sha384()

    elif digested_hash == sha512:

        hash_type = hashlib.sha512()

    try:
        with open(wordlist, 'r', encoding="utf-8", errors="ignore") as wordlist:
            for word in wordlist:
                word = word.strip()
                generated_hash = hashlib.new(hash_type.name)
                generated_hash.update(word.encode('utf-8'))
                generated_hash = generated_hash.hexdigest()

                if generated_hash == hash_to_crack:
                    print(
                        colorama.Fore.GREEN + f"Original text for hash '{hash_to_crack}' found: {word}" + colorama.Fore.RESET)
                    break
                else:
                    print(
                        colorama.Fore.RED + f"No match found in the dictionary for hash '{hash_to_crack}'" + colorama.Fore.RESET)

    except FileNotFoundError:
        print(colorama.Fore.RED + f"Dictionary file not found at '{wordlist}'" + colorama.Fore.RESET)


if user_input == 1:
    hash_type_detetor()
elif user_input == 2:
    hash_generator()
elif user_input == 3:
    hash_cracker()
elif user_input == 4:
    os.system('cls')
    exit()

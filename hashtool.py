#Thanks to the teacher & class
import colorama
import pyfiglet
import hashlib
import os
import multiprocessing

colorama.init()

def clear_screen():
    os.system('cls')

def display_menu():
    banner = pyfiglet.figlet_format("Ark Ang3l hash Cracker", font="digital")
    menu = '''
    [1] Hash Type Detector
    [2] Hash Generator
    [3] Hash Cracker
    [4] File Hash Integrity Check
    [5] Exit
    '''
    print((colorama.Fore.RED + banner + colorama.Fore.RESET))
    print((colorama.Fore.GREEN + menu + colorama.Fore.RESET))

def get_user_choice():
    try:
        user_input = int(input(colorama.Fore.BLUE + "Enter your choice: " + colorama.Fore.RESET))
        return user_input
    except ValueError:
        return None

def hash_type_detector():
    hash = input(colorama.Fore.CYAN + 'please input your hash to detect: ' + colorama.Fore.RESET)

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

def file_integrity_check():
    file_path = input(colorama.Fore.YELLOW + 'Enter the path of the file: ' + colorama.Fore.RESET)
    hash_algorithm = input(colorama.Fore.YELLOW + 'Enter the hash algorithm (e.g., sha256): ' + colorama.Fore.RESET)
    
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
            calculated_hash = hashlib.new(hash_algorithm)
            calculated_hash.update(file_data)
            file_hash = calculated_hash.hexdigest()

            print(colorama.Fore.GREEN + f"File Hash: {file_hash}" + colorama.Fore.RESET)

    except FileNotFoundError:
        print(colorama.Fore.RED + f"File not found at '{file_path}'" + colorama.Fore.RESET)

def hash_cracker():
    hash_to_crack = input(colorama.Fore.YELLOW + 'Please input your hash to crack: ' + colorama.Fore.RESET)

    # Automatically detect hash type based on the length of the hash
    hash_type = detect_hash_type(hash_to_crack)

    if hash_type is None:
        print(colorama.Fore.RED + "Unable to detect hash type. Please provide a valid hash." + colorama.Fore.RESET)
        return

    wordlist = input(colorama.Fore.YELLOW + 'Please input your wordlist path: ' + colorama.Fore.RESET)

    num_cores = multiprocessing.cpu_count()
    print(colorama.Fore.CYAN + f"Using {num_cores} CPU cores for hash cracking..." + colorama.Fore.RESET)

    pool = multiprocessing.Pool(processes=num_cores)

    try:
        with open(wordlist, 'r') as wordlist_file:
            words = wordlist_file.readlines()
            results = pool.map(crack_hash, [(word.strip(), hash_to_crack, hash_type) for word in words])

            for result in results:
                if result is not None:
                    print(colorama.Fore.GREEN + f"Original text for hash '{hash_to_crack}' found: {result}" + colorama.Fore.RESET)
                    break
            else:
                print(colorama.Fore.RED + f"No match found in the dictionary for hash '{hash_to_crack}'" + colorama.Fore.RESET)

    except FileNotFoundError:
        print(colorama.Fore.RED + f"Dictionary file not found at '{wordlist}'" + colorama.Fore.RESET)

    finally:
        pool.close()
        pool.join()

def crack_hash(data):
    word, hash_to_crack, hash_type = data
    generated_hash = hashlib.new(hash_type)
    generated_hash.update(word.encode('utf-8'))
    generated_hash = generated_hash.hexdigest()

    if generated_hash == hash_to_crack:
        return word

def detect_hash_type(hash_value):
    hash_length = len(hash_value)

    if hash_length == 32:
        return 'md5'
    elif hash_length == 40:
        return 'sha1'
    elif hash_length == 56:
        return 'sha224'
    elif hash_length == 64:
        return 'sha256'
    elif hash_length == 96:
        return 'sha384'
    elif hash_length == 128:
        return 'sha512'
    elif hash_length == 64 and hash_value.startswith('$'):
        return 'sha3_512'
    elif hash_length == 56 and hash_value.startswith('$'):
        return 'sha3_224'
    elif hash_length == 40 and hash_value.startswith('$'):
        return 'sha3_256'
    elif hash_length == 96 and hash_value.startswith('$'):
        return 'sha3_384'
    elif hash_length == 40 and hash_value.startswith('2'):
        return 'blake2s'
    elif hash_length == 64 and hash_value.startswith('2'):
        return 'blake2b'
    else:
        return None

if __name__ == "__main__":
    while True:
        clear_screen()
        display_menu()
        user_choice = get_user_choice()

        if user_choice == 1:
            hash_type_detector()
        elif user_choice == 2:
            hash_generator()
        elif user_choice == 3:
            hash_cracker()
        elif user_choice == 4:
            file_integrity_check()
        elif user_choice == 5:
            clear_screen()
            print("Exiting the program. Goodbye!")
            break  # Exit the loop

        input("Press Enter to continue...")  # Wait for user input before clearing the screen

from scipy.stats import entropy
from base64 import b64decode,b64encode
from hashlib import md5,sha256,sha1
import requests
from random import randint

#rewrite this whole thing to be more user friendly for example make it so that it will work like: HackMate MD5 "string" or HackMate MD5 -f "path to file" etc..
def asciiart():
    i=randint(0,2)
    if i==0:
        print(" _   _            _     ___  ___      _\n| | | |          | |    |  \/  |     | |\n| |_| | __ _  ___| | __ | .  . | __ _| |_ ___ \n|  _  |/ _` |/ __| |/ / | |\/| |/ _` | __/ _ \n| | | | (_| | (__|   <  | |  | | (_| | ||  __/\n\_| |_/\__,_|\___|_|\_\ \_|  |_/\__,_|\__\___|")
    elif i==1:
        print('''
        _  _   __    ___  __ _    _  _   __  ____  ____ 
        / )( \ / _\  / __)(  / )  ( \/ ) / _\(_  _)(  __)
        ) __ (/    \( (__  )  (   / \/ \/    \ )(   ) _) 
        \_)(_/\_/\_/ \___)(__\_)  \_)(_/\_/\_/(__) (____)
             ''')
    elif i==2:
        print('''

        $$\   $$\                     $$\             $$\      $$\            $$\               
        $$ |  $$ |                    $$ |            $$$\    $$$ |           $$ |              
        $$ |  $$ | $$$$$$\   $$$$$$$\ $$ |  $$\       $$$$\  $$$$ | $$$$$$\ $$$$$$\    $$$$$$\  
        $$$$$$$$ | \____$$\ $$  _____|$$ | $$  |      $$\$$\$$ $$ | \____$$\\_$$  _|  $$  __$$\ 
        $$  __$$ | $$$$$$$ |$$ /      $$$$$$  /       $$ \$$$  $$ | $$$$$$$ | $$ |    $$$$$$$$ |
        $$ |  $$ |$$  __$$ |$$ |      $$  _$$<        $$ |\$  /$$ |$$  __$$ | $$ |$$\ $$   ____|
        $$ |  $$ |\$$$$$$$ |\$$$$$$$\ $$ | \$$\       $$ | \_/ $$ |\$$$$$$$ | \$$$$  |\$$$$$$$\ 
        \__|  \__| \_______| \_______|\__|  \__|      \__|     \__| \_______|  \____/  \_______|
''')
                                                                          
def menu():
    asciiart()
    print("1. Caesar cipher\n2. Vigenere cipher\n3. Entropy calculator\n4. Base64\n5. Hash\n6. Exit")
    choice=input("Choose option: ")
    if choice=="1":
        caesar_decrypt()
    elif choice=="2":
        vigenere_decrypt()
    elif choice=="3":
        entropy_calc()
    elif choice=="4":
        base_64()
    elif choice=="5":
        hash()
    elif choice=="6":
        exit()
    else:
        print("Invalid choice")
        return

def caesar_decrypt():
    cipher=input("ciphertext:")
    for i in range(25):
        plaintext=""
        for char in cipher:
            if ord(char)>47 and ord(char)<57:
                plaintext+=char
            elif ord(char)>64 and ord(char)<91:
                z=ord(char)+i
                if z>91:
                    z=z%91+65
                plaintext+=chr(z)
            elif ord(char)>96 and ord(char)<123:
                z=ord(char)+i
                if z>122:
                    z=z%122+96
                plaintext+=chr(z)
            else:
                plaintext+=char
        print("Key: %s, Plaintext: %s" % (i, plaintext))
#

#caesar_decrypt(cipher)
def vigenere_decrypt(ciphertext):
    ciphertext=input("ciphertext: ")
    key=input("key: ")
    plaintext = ""
    key_len = len(key)
    key_id = 0
    for c in ciphertext:
        if c.isalpha():
            # determine the offset to use based on the case of the character
            if c.isupper():
                offset = ord('A')
            else:
                offset = ord('a')

            # determine the distance to shift the character based on the
            # corresponding character in the key
            key_char = key[key_id % key_len]
            shift = ord(key_char.lower()) - ord('a')

            # apply the shift to the current character and add it to the plaintext
            plaintext += chr((ord(c) - offset - shift) % 26 + offset)
            key_id += 1
        else:
            # non-alphabetic characters are added to the plaintext unchanged
            plaintext += c

    return plaintext

def entropy_calc():
    label=[]
    choice=input("1. From file\n2. From input\n")
    if choice=="1":
        path = input("Provide path to file:")
        f = open(path, "r")
        cipher = f.read()
        f.close()
    elif choice=="2":
        cipher=input("cipher:")
        
    else:
        print("Invalid choice")
        return
    label[:0]=cipher
    for i in range(len(label)):
        label[i]=ord(label[i])
    print(entropy(label))

#entropy_calc()

def base_64():
    #usunąc stad choice i dać w menu wyboru encode lub decode
    choice = input("1. Encode\n2. Decode\n")
    input_type=input("1. From file\n2. From input\n")
    if input_type=="1":
        path = input("Provide path to file:")
        f = open(path, "r")
        cipher = f.read()
        f.close()
    elif input_type=="2":
        cipher=input("cipher:")
        
    else:
        print("Invalid choice")
        return
    if choice=="1":
        print(b64encode(cipher.encode('utf-8')))
    elif choice=="2":
        print(b64decode(cipher))
    else:
        print("Invalid choice")
        return
#base_64()
def hash():
    choice=input("1. MD5\n2. SHA1\n3. SHA256\n")
    input_type=input("1. From file\n2. From input\n")
    if input_type=="1":
        path = input("Provide path to file:")
        f = open(path, "r")
        cipher = f.read()
        f.close()
    elif input_type=="2":
        cipher=input("cipher:")
        
    else:
        print("Invalid choice")
        return
    if choice=="1":
        print(md5(cipher.encode('utf-8')).hexdigest())
    elif choice=="2":
        print(sha1(cipher.encode('utf-8')).hexdigest())
    elif choice=="3":
        print(sha256(cipher.encode('utf-8')).hexdigest())
    else:
        print("Invalid choice")
        return
#hash() 
menu()

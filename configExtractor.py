import pefile
from Crypto.Cipher import ARC4
import binascii
import re
import urllib.request
import argparse

def rc4_decrypt(key, data):
    cipher = ARC4.new(key)
    decrypted = cipher.decrypt(data)
    return decrypted

def extractPayload(file):
    # Extract and decrypt the 2nd stage
    print("[+] Extracting the payload...")
    pe = pefile.PE(file)
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(entry.name) == "RC_DATA" or "RCData":
            new_dirs = entry.directory
            for res in new_dirs.entries:
                data_rva = res.directory.entries[0].data.struct.OffsetToData
                size = res.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                key = data[12:27]
                print("[+] Done !")
                return rc4_decrypt(key, data[28:])
    print("[-] Something went wrong when extraction the payload")

def rotl(b):
    bit = (b >> 7) & 1
    return ((b << 1) | bit) & 0xFF

def rot(inputed, amount):
    result = []
    for b in inputed:
        for i in range(amount):
            b = rotl(b)
        result.append(b)
    return result


def extractBlob(arg):
    # Extract the whole section where the config is
    print("[+] Extracting the config...")
    pe=pefile.PE(data = arg)
    for section in pe.sections:
        if ".rdata" in str(section.Name):
            print("[+] Done !")
            return section.get_data()
    print("[-] Something went wrong when extraction the config")

def main():
    parser = argparse.ArgumentParser(description='Decrypt the cruloader config')
    parser.add_argument('-f', '--file', help='Path of the binary file', required=True)
    args = parser.parse_args()
    pe = extractPayload(args.file)
    data = extractBlob(pe)
    print("[+] Bruteforcing the config...")
    for rotAmount in range(1,10): #Bruteforce the ROT amount
        rotated = rot(data, rotAmount)
        for xorKey in range(300): # Bruteforce the XOR key
            result = ""
            for b in rotated:
                result += chr(b ^ xorKey)
            if "http" in result:
                pattern = "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)?" #hope you like my tiny regex
                config = re.search(pattern, result)
                print(f"[+] Found config ! {config[0]}")
                exit()
    print("[-] Couldn't find any config :'(")

if __name__ == "__main__":
    main()
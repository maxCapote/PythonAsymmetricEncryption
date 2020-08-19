from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os
import argparse

def gen_key_pair(size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_pair():
    pass

def load_key(key):
    pass

def encrypt(target):
    pass

def decrypt(target):
    pass

def Main():
    parser = argparse.ArgumentParser(description = 'command-line args')
    parser.add_argument('-m', '--mode', help='generate key pair, encrypt, or decrypt')
    parser.add_argument('-s', '--size', help='size of key pair in bytes for generation')
    parser.add_argument('-k', '--key', help='asymmetric key for encrypting or decrypting')
    parser.add_argument('-t', '--target', help='file or directory for encryption or decryption')
    args = parser.parse_args()

    if args.mode == 'generate':
        print('things')
    else:
        print('Usage: python asym_enc.py [options]')

if __name__ == '__main__':
    Main()

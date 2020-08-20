from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import argparse

def gen_key_pair(size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
        backend=default_backend()
    )
    return private_key.public_key(), private_key

def save_public_key(public_key):
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('rsa_public.pem', 'wb') as fout:
        fout.write(pem_public)

def save_private_key(private_key):
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('rsa_private.pem', 'wb') as fout:
        fout.write(pem_private)

def load_public_key(key):
    with open(key, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def load_private_key(key):
    with open(key, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def encrypt_target(public_key, target):
    if os.path.isfile(target):
        encrypt_file(public_key, target)
    else:
        for root, _, files in os.walk(target):
            for file in files:
                encrypt_file(public_key, os.path.join(root, file))
    pass

def decrypt_target(private_key, target):
    if os.path.isfile(target):
        decrypt_file(private_key, target)
    else:
        for root, _, files in os.walk(target):
            for file in files:
                decrypt_file(private_key, os.path.join(root, file))
    pass

def encrypt_file(public_key, target):
    with open(target, 'rb') as fin:
        plaintext = fin.read()
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(target, 'wb') as fout:
        fout.write(ciphertext)

def decrypt_file(private_key, target):
    with open(target, 'rb') as fin:
        ciphertext = fin.read()
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(target, 'wb') as fout:
        fout.write(plaintext)

def Main():
    parser = argparse.ArgumentParser(description = 'command-line args')
    parser.add_argument('-m', '--mode', help='generate, encrypt, or decrypt')
    parser.add_argument('-s', '--size', help='size of key pair in bytes for generation')
    parser.add_argument('-k', '--key', help='asymmetric key for encrypting or decrypting')
    parser.add_argument('-t', '--target', help='file or directory for encryption or decryption')
    args = parser.parse_args()

    if args.mode == 'generate':
        print('[+] generating key pair')
        public_key, private_key = gen_key_pair(int(args.size))
        print('[+] saving public key to file')
        save_public_key(public_key)
        print('[+] saving private key to file')
        save_private_key(private_key)
        print('[+] done')
    elif args.key is not None and args.target is not None:
        if args.mode == 'encrypt':
            print('[+] loading public key')
            public_key = load_public_key(args.key)
            print('[+] encrypting file(s)')
            encrypt_target(public_key, args.target)
        elif args.mode == 'decrypt':
            print('[+] loading private key')
            private_key = load_private_key(args.key)
            print('[+] decrypting file(s)')
            decrypt_target(private_key, args.target)
        print('[+] done')
    else:
        print('Usage: python asym_enc.py [-m MODE] [options]')

if __name__ == '__main__':
    Main()

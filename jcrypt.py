import os
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_key_from_password(password):
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, private_key):
    with open(file_path, 'rb') as f:
        data = f.read()

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(private_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    with open(file_path + '.jcrypt', 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(file_path, private_key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(private_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(file_path[:-7], 'wb') as f:
        f.write(decrypted_data)

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt files.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--encrypt', action='store_true', help='Encrypt the file')
    group.add_argument('--decrypt', action='store_true', help='Decrypt the file')
    parser.add_argument('--file', required=True, help='File to be encrypted or decrypted')
    parser.add_argument('--private-key', required=True, help='Private key for encryption or decryption')

    args = parser.parse_args()

    private_key = generate_key_from_password(args.private_key)

    if args.encrypt:
        encrypt_file(args.file, private_key)
        print(f'{args.file} encrypted successfully.')
    elif args.decrypt:
        decrypt_file(args.file, private_key)
        print(f'{args.file} decrypted successfully.')

if __name__ == "__main__":
    main()

import os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac

def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = kdf.derive(passphrase.encode())
    return key

def enc(fich, passphrase):
    with open(fich, 'rb') as file:
        plaintext = file.read()

    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(fich + '.enc', 'wb') as file:
        file.write(salt + nonce + ciphertext)

def dec(fich, passphrase):
    with open(fich, 'rb') as file:
        data = file.read()

    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]

    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    with open(fich + '.dec', 'wb') as file:
        file.write(plaintext)

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 pbenc_chacha20poly1305.py [enc|dec] [fich]")
        return

    operation = sys.argv[1]
    fich = sys.argv[2]
    passphrase = input("Enter passphrase: ")

    if operation == 'enc':
        enc(fich, passphrase)
    elif operation == 'dec':
        dec(fich, passphrase)
    else:
        print("Error: Invalid operation. Use 'enc' or 'dec'.")

if __name__ == '__main__':
    main()

import sys, os, cryptography
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_keys(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 64,
        salt = salt,
        iterations = 480000,
    )
    keys = kdf.derive(passphrase.encode())
    enc_key = keys[:32]
    mac_key = keys[32:]
    return enc_key, mac_key


def calc_hmac(key, text):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(text)
    signature = h.finalize()
    return signature


def encrypt_then_mac(plaintext, enc_key, mac_key):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    mac = calc_hmac(mac_key, ciphertext)
    return nonce, ciphertext, mac


def verify_mac(mac_key, ciphertext, mac):
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(ciphertext)
    h.verify(mac)


def decrypt_then_verify(nonce, ciphertext, mac, enc_key, mac_key):
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    decryptor = cipher.encryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    try:
        verify_mac(mac_key, ciphertext, mac)
        return plaintext
    except cryptography.exceptions.InvalidSignature:
        print("MAC verification failed!")


def enc(fich, passphrase):
    with open(fich, 'rb') as file:
        plaintext = file.read()
    
    salt = os.urandom(16)
    enc_key, mac_key = derive_keys(passphrase, salt)
    nonce, ciphertext, mac = encrypt_then_mac(plaintext, enc_key, mac_key)
    
    with open(fich + '.enc', 'wb') as file:
        file.write(salt + nonce + ciphertext + mac)


def dec(fich, passphrase):
    with open(fich, 'rb') as file:
        data = file.read()
    
    salt = data[:16]
    nonce = data[16:32]
    ciphertext = data[32:-32]
    mac = data[-32:]
    
    enc_key, mac_key = derive_keys(passphrase, salt)
    
    plaintext = decrypt_then_verify(nonce, ciphertext, mac, enc_key, mac_key)
    
    with open(fich + '.dec', 'wb') as file:
        file.write(plaintext)


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 pbenc_aes_ctr_hmac.py [enc|dec] [fich]")
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

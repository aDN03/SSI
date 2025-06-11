import os
import sys
import struct
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from getpass import getpass

def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def setup():
    print("Não é mais necessário gerar uma chave. Utilizamos uma passphrase para derivar a chave.")

def encrypt(finput):
    passphrase = getpass("Digite a passphrase: ")
    salt = os.urandom(16) 
    key = derive_key(passphrase, salt)
    
    nonce = os.urandom(16)
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()

    output_file_path = finput + ".enc"
    with open(finput, "rb") as input_file, open(output_file_path, "wb") as output_file:
        output_file.write(salt)
        output_file.write(nonce)
        while chunk := input_file.read(4096):
            output_file.write(encryptor.update(chunk))

    print(f"Texto cifrado e salvo em {output_file_path}")

def decrypt(finput):
    passphrase = getpass("Digite a passphrase: ")

    with open(finput, "rb") as input_file:
        salt = input_file.read(16)
        nonce = input_file.read(16) 
        key = derive_key(passphrase, salt)
        
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None)
        decryptor = cipher.decryptor()

        output_file_path = finput + ".dec"
        with open(output_file_path, "wb") as output_file:
            while chunk := input_file.read(4096):
                output_file.write(decryptor.update(chunk))

    print(f"Texto decifrado e salvo em {output_file_path}")

def main():
    if len(sys.argv) < 3:
        print("Uso: python cfich_chacha20.py <setup/enc/dec> <arquivo>")
        return
    
    operation = sys.argv[1]
    
    if operation == "setup":
        setup()
    elif operation == "enc" and len(sys.argv) == 3:
        encrypt(sys.argv[2])
    elif operation == "dec" and len(sys.argv) == 3:
        decrypt(sys.argv[2])
    else:
        print("Comando inválido ou argumentos insuficientes.")

if __name__ == "__main__":
    main()

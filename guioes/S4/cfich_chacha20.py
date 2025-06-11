import os
import sys
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def setup(fkey):
    key = os.urandom(32)
    with open(fkey, "wb") as key_file:
        key_file.write(key)
        print(f"Tamanho da chave lida: {len(key)} bytes")
    print(f"Chave gerada e salva em {fkey}")

def encrypt(fkey, finput):
    with open(fkey, "rb") as key_file:
        key = key_file.read(32)
        print(f"Tamanho da chave lida: {len(key)} bytes") 
        print(f"Chave lida: {key}")
    
    if len(key) != 32:
        print("Chave inválida.")
        return

    nonce = os.urandom(16) 
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()

    output_file_path = finput + ".enc"
    with open(finput, "rb") as input_file, open(output_file_path, "wb") as output_file:
        output_file.write(nonce) 
        while chunk := input_file.read(4096):
            output_file.write(encryptor.update(chunk))

    print(f"Texto cifrado e salvo em {output_file_path}")


def decrypt(fkey, finput):
    with open(fkey, "rb") as key_file:
        key = key_file.read()

    with open(finput, "rb") as input_file:
        nonce = input_file.read(16)
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
        print("Uso: python cfich_chacha20.py <setup/enc/dec> <arquivo> [chave]")
        return
    
    operation = sys.argv[1]
    
    if operation == "setup":
        setup(sys.argv[2])
    elif operation == "enc" and len(sys.argv) == 4:
        encrypt(sys.argv[3], sys.argv[2])
    elif operation == "dec" and len(sys.argv) == 4:
        decrypt(sys.argv[3], sys.argv[2])
    else:
        print("Comando inválido ou argumentos insuficientes.")

if __name__ == "__main__":
    main()

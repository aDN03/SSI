import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def setup(fkey):
    key = os.urandom(32) 
    with open(fkey, "wb") as key_file:
        key_file.write(key)
    print(f"Chave gerada e salva em {fkey}")

def encrypt(fkey, finput):
    with open(fkey, "rb") as key_file:
        key = key_file.read()

    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()

    output_file_path = finput + ".enc"
    with open(finput, "rb") as input_file, open(output_file_path, "wb") as output_file:
        output_file.write(nonce)
        while chunk := input_file.read(4096):
            output_file.write(encryptor.update(chunk))
        output_file.write(encryptor.finalize())

    print(f"Texto cifrado e salvo em {output_file_path}")

def decrypt(fkey, finput):
    with open(fkey, "rb") as key_file:
        key = key_file.read()

    with open(finput, "rb") as input_file:
        nonce = input_file.read(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        decryptor = cipher.decryptor()

        output_file_path = finput + ".dec"
        with open(output_file_path, "wb") as output_file:
            while chunk := input_file.read(4096):
                output_file.write(decryptor.update(chunk))
            output_file.write(decryptor.finalize())

    print(f"Texto decifrado e salvo em {output_file_path}")

def main():
    if len(sys.argv) < 3:
        print("Uso: python cfich_aes_ctr.py <setup/enc/dec> <arquivo> [chave]")
        return
    
    operation = sys.argv[1]
    
    if operation == "setup":
        setup(sys.argv[2])
    elif operation == "enc" and len(sys.argv) == 4:
        encrypt(sys.argv[2], sys.argv[3])
    elif operation == "dec" and len(sys.argv) == 4:
        decrypt(sys.argv[2], sys.argv[3])
    else:
        print("Comando inválido ou argumentos insuficientes.")

if __name__ == "__main__":
    main()

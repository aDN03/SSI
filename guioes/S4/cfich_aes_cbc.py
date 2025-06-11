import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def setup(fkey):
    key = os.urandom(32)
    with open(fkey, "wb") as key_file:
        key_file.write(key)
    print(f"Chave gerada e salva em {fkey}")

def encrypt(fkey, finput):
    with open(fkey, "rb") as key_file:
        key = key_file.read()

    iv = os.urandom(16) 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()

    output_file_path = finput + ".enc"
    with open(finput, "rb") as input_file, open(output_file_path, "wb") as output_file:
        output_file.write(iv)
        while chunk := input_file.read(4096):
            output_file.write(encryptor.update(padder.update(chunk)))
        output_file.write(encryptor.update(padder.finalize()))
        output_file.write(encryptor.finalize())

    print(f"Texto cifrado e salvo em {output_file_path}")

def decrypt(fkey, finput):
    with open(fkey, "rb") as key_file:
        key = key_file.read()

    with open(finput, "rb") as input_file:
        iv = input_file.read(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        unpadder = padding.PKCS7(128).unpadder()
        output_file_path = finput + ".dec"
        with open(output_file_path, "wb") as output_file:
            decrypted_data = decryptor.update(input_file.read()) + decryptor.finalize()
            output_file.write(unpadder.update(decrypted_data) + unpadder.finalize())

    print(f"Texto decifrado e salvo em {output_file_path}")

def main():
    if len(sys.argv) < 3:
        print("Uso: python cfich_aes_cbc.py <setup/enc/dec> <arquivo> [chave]")
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

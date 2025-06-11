from itertools import product
import string
import sys
from guioes.S3.a100715.vigenere import *

def vigenere_attack (tamanho_chave: int, criptograma, sequencia_palavras):
    alfabeto = string.ascii_uppercase  # Alfabeto A-Z

    for combinacao in product(alfabeto, repeat=tamanho_chave):
        dec = vigenere_dec(combinacao, criptograma)
        if any(palavra in dec for palavra in sequencia_palavras):
                print(f"Chave: {''.join(combinacao)}")
                print(f"Texto: {dec}")


def main():
    tamanho_cifra = int(sys.argv[1])
    cifra = sys.argv[2]
    palavras = sys.argv[3:]

    vigenere_attack(tamanho_cifra, cifra, palavras)

if __name__ == "__main__":
    main();
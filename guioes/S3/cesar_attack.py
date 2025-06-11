import sys
from cesar import cesar_dec

def preproc(text):
    return "".join(c.upper() for c in text if c.isalpha())

def cesar_attack(cifra, palavras):
    print(f"Texto cifrado: {cifra}")
    print(f"Palavras: {palavras}")
    alf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    for i in range(len(alf)):
        dec = cesar_dec(-i, cifra)
        for word in palavras:
            if dec.find(word) != -1:
                print(f"Chave: {alf[i]}")
                print(f"Texto: {dec}")
        
def main():
    cifra = sys.argv[1]
    palavras = sys.argv[2:]

    cesar_attack(cifra, palavras)

if __name__ == "__main__":
    main()
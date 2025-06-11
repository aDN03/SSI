import os
import sys

def gerar_chave(num_bytes, ficheiro_saida):
    chave = os.urandom(num_bytes)
    with open(ficheiro_saida, 'wb') as f:
        f.write(chave)

def xor_bytes(data, chave):
    return bytes([b ^ c for b, c in zip(data, chave)])

def cifrar(ficheiro_msg, ficheiro_chave):
    with open(ficheiro_msg, 'rb') as f:
        mensagem = f.read()

    with open(ficheiro_chave, 'rb') as f:
        chave = f.read()

    if len(chave) < len(mensagem):
        sys.exit(1)

    cifrado = xor_bytes(mensagem, chave[:len(mensagem)])
    ficheiro_saida = ficheiro_msg + '.enc'
    with open(ficheiro_saida, 'wb') as f:
        f.write(cifrado)

def decifrar(ficheiro_enc, ficheiro_chave):
    with open(ficheiro_enc, 'rb') as f:
        cifrado = f.read()

    with open(ficheiro_chave, 'rb') as f:
        chave = f.read()

    if len(chave) < len(cifrado):
        sys.exit(1)

    decifrado = xor_bytes(cifrado, chave[:len(cifrado)])
    ficheiro_saida = ficheiro_enc + '.dec'
    with open(ficheiro_saida, 'wb') as f:
        f.write(decifrado)


def main():
    if len(sys.argv) < 4:
        sys.exit(1)

    operacao = sys.argv[1]

    if operacao == 'setup':
        num_bytes = int(sys.argv[2])
        ficheiro_chave = sys.argv[3]
        gerar_chave(num_bytes, ficheiro_chave)

    elif operacao == 'enc':
        ficheiro_msg = sys.argv[2]
        ficheiro_chave = sys.argv[3]
        cifrar(ficheiro_msg, ficheiro_chave)

    elif operacao == 'dec':
        ficheiro_enc = sys.argv[2]
        ficheiro_chave = sys.argv[3]
        decifrar(ficheiro_enc, ficheiro_chave)

    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
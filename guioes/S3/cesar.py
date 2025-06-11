import sys

def preproc(text):
    return "".join(c.upper() for c in text if c.isalpha())

def cesar_enc(n_saltos, text):
    alb = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    text = preproc(text)
    enc = ""
    for c in text:
        if c.isalpha():
            enc += alb[(alb.index(c) + n_saltos) % 26]
    return enc

def cesar_dec(n_saltos, text):
    return cesar_enc(n_saltos, text)

def main():
    if len(sys.argv) != 4:
        print("Uso: cesar <enc|dec> <n> <texto>")
        return 1

    operation = sys.argv[1]

    key = sys.argv[2]

    message = preproc(sys.argv[3])

    alb = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    n_saltos = alb.index(key) 

    if operation == "enc":
        print(cesar_enc(n_saltos, message))
    elif operation == "dec":
        print(cesar_dec(-n_saltos, message))
    else:
        print("Opção inválida, use 'enc' para cifrar ou 'dec' para decifrar.")
        return 1
    
    return 0

if __name__ == "__main__":
    main()

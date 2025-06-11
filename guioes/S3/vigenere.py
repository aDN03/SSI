from cesar import cesar_dec, cesar_enc

def preproc(text):
    return "".join(c.upper() for c in text if c.isalpha())

def vigenere_enc(key, text):
    alb = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    enc = ""
    len_key = len(key)
    i = 0
    for c in text:
        enc += cesar_enc(alb.index(key[i]), c)
        if i < len_key - 1:
            i += 1
        else:
            i = 0

    return enc
        
def vigenere_dec(key, text):
    alb = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    enc = ""
    len_key = len(key)
    i = 0
    for c in text:
        enc += cesar_enc(-alb.index(key[i]), c)
        if i < len_key - 1:
            i += 1
        else:
            i = 0

    return enc


def main():
    import sys
    operation = sys.argv[1]
    key = sys.argv[2]
    text = sys.argv[3]
    if operation == "enc":
        enc = vigenere_enc(key, text)
        print(enc)
    elif operation == "dec":
        dec = vigenere_dec(key, text)
        print(dec)



if __name__ == "__main__":
    main()
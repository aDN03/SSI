import asyncio
import base64
import os
import sys

from assistant import (
    encrypt_message,
    get_Data,
    mkpair,
    unpair,
    validate_certificate,
    validate_certificate_user_id,
)
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa  # Importando rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
    load_pem_public_key,
    pkcs12,
)
from interface import display_help, display_welcome_banner


p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
pn = dh.DHParameterNumbers(p, g)
parameters = pn.parameters()

max_msg_size = 9999


class Client:
    def __init__(self, p12_file):
        self.msg_cnt = 0
        (
            self.cert,
            self.user_id,
            self.ca_name,
            self.private_key,
            self.public_key,
            self.not_valid_befora,
            self.not_valid_after,
        ) = get_Data(p12_file)

        self.dh_private_key = parameters.generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()
        self.shared_key = None
        self.share_user_id = None
        self.chave_criptografar = None

        print(f"\n[+] Certificado do cliente carregado:")
        print(f"    Dono (CN): {self.user_id}")
        print(f"    CA: {self.ca_name}")
        print(f"    ID (Pseudônimo): {self.user_id}")

        print("\n[+] A validar Servidor")

    async def process(self, msg=b""):
        self.msg_cnt += 1

        if self.msg_cnt == 1:
            msg = self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            return msg
        elif self.msg_cnt == 2:
            rest_server, cert_server = unpair(msg)
            dh_server, signature = unpair(rest_server)

            dh_server = serialization.load_der_public_key(dh_server)

            dh_server = dh_server.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            cert_server = x509.load_pem_x509_certificate(cert_server)
            validate_certificate(cert_server)
            public_key_server = cert_server.public_key()

            try:
                public_key_server.verify(
                    signature,
                    mkpair(
                        dh_server,
                        self.dh_public_key.public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        ),
                    ),
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )

                print("[OK] Assinatura verificada com sucesso!")
            except Exception as e:
                print("[ERROR] Falha na verificação da assinatura:", e)

            msg = mkpair(
                self.dh_public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                dh_server,
            )

            msg = self.private_key.sign(
                msg,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            msg = mkpair(msg, self.cert.public_bytes(Encoding.PEM))

            self.shared_key = self.dh_private_key.exchange(
                load_der_public_key(dh_server)
            )
            print("[OK] Chave compartilhada estabelecida com sucesso!")
            print("[OK] Conexão estabelecida com sucesso!\n")

            return msg

        elif self.msg_cnt >= 3:
            if msg != b"IGNORE":
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"dh session",
                ).derive(self.shared_key)
                nonce, ciphertext = unpair(msg)
                aesgcm = AESGCM(derived_key)
                msg = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
                command_bytes, content = msg.split(b"?", 1)
                command = command_bytes.decode()

                if command == "1R":
                    print(f"ID do ficheiro: {msg.split(b'?')[1].decode()}")

                elif command == "2R":
                    content, file_name = unpair(msg.split(b"?")[1])
                    file_data, chave = unpair(content)

                    chave = self.private_key.decrypt(
                        base64.b64decode(chave),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    try:
                        fernet = Fernet(chave)
                        decrypted_data = fernet.decrypt(file_data)
                    except Exception as e:
                        print(f"\n[ERRO] Falha ao descriptografar o ficheiro: {e}")
                        return None

                    print(f"\n[+] ID do ficheiro: {file_name.decode()}")
                    print(f"\n[+] Conteúdo do ficheiro '{file_name.decode()}':")
                    print("|", "-" * 40, "|")
                    for line in decrypted_data.decode().split("\n"):
                        print(f"|  {line.ljust(38)}  |")
                    print("|", "-" * 40, "|")
                    print("\n[+] Ficheiro lido com sucesso!")

                elif command == "3R":
                    file_id = content.decode()
                    print(f"\n[+] Ficheiro '{file_id}' eliminado com sucesso!")

                elif command == "4R":
                    chave, cert = unpair(content)
                    cert = x509.load_pem_x509_certificate(cert)
                    if not validate_certificate_user_id(cert, self.share_user_id):
                        print("\n[ERRO] O certificado não é válido para o utilizador.")
                        return None

                    self.share_user_id = None
                    chave = self.private_key.decrypt(
                        base64.b64decode(chave),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    public_key_share_client = cert.public_key()

                    encrypted_key = public_key_share_client.encrypt(
                        chave,
                        padding.OAEP(
                            algorithm=hashes.SHA256(),
                            label=None,
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        ),
                    )

                    return encrypt_message(self.shared_key, b"4R?" + encrypted_key)

                elif command == "4RR":
                    if content == b"1":
                        print("Ficheiro partilhado com sucesso!")

                elif command == "5R":
                    if content == b"1":
                        print("Permissão revogada com sucesso!")

                elif command == "6R":
                    content = content.decode()
                    try:
                        print("\n[+] Lista de ficheiros:")
                        print("|", "-" * 80, "|")
                        for line in content.split(";"):
                            line = line.strip()
                            if not line or "--" not in line:
                                continue
                            id, nome = line.split("--", 1)
                            print(f"| Id: {id.ljust(38)} Nome: {nome.ljust(38)}   |")
                        print("|", "-" * 80, "|")

                    except Exception as e:
                        print(f"\n[ERROR] Falha a mostrar lista: {e}")

                elif command == "7R":
                    rest, key = unpair(content)
                    file_id, file_path = unpair(rest)
                    key = key.decode()
                    file_path = file_path.decode()
                    file_id = file_id.decode()

                    key = base64.b64decode(key)

                    key = self.private_key.decrypt(
                        key,
                        padding.OAEP(
                            algorithm=hashes.SHA256(),
                            label=None,
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        ),
                    )

                    fernet = Fernet(key)
                    with open(file_path, "rb") as file:
                        file_data = file.read()
                    encrypted_data = fernet.encrypt(file_data)

                    file_name = os.path.basename(file_path)

                    return encrypt_message(
                        self.shared_key,
                        b"7R?"
                        + mkpair(
                            file_id.encode(), mkpair(file_name.encode(), encrypted_data)
                        ),
                    )

                elif command == "7RR":
                    print(f"ID do ficheiro que foi substituido: {content.decode()}")

                elif command == "8R":
                    content = content.decode()
                    content = content.split(";")
                    print("Owner: " + content[0])
                    print("File Name: " + content[1])
                    print("Permissions: " + content[2])
                    print("File Size: " + content[3] + " bytes")

                elif command == "8RG":
                    content = content.decode()
                    content = content.split(";")
                    print("File Name: " + content[0])
                    print("Permissions: " + content[1])
                    print("File Size: " + content[2] + " bytes")

                elif command == "9R":
                    print(f"\n[+] Grupo '{content.decode()}' criado com sucesso!")

                elif command == "10R":
                    print(f"\n[+] Grupo '{content.decode()}' eliminado com sucesso!")
                elif command == "11R":
                    if content == b"1":
                        print(
                            f"\n[+] Utilizador '{self.share_user_id}' adicionado ao grupo com sucesso!"
                        )
                        self.share_user_id = None
                    else:
                        rest, keys = unpair(content)
                        group_id, cert = unpair(rest)
                        keys = keys.decode().split("||")
                        cert = x509.load_pem_x509_certificate(cert)

                        file_keys = []
                        for key in keys:
                            key = base64.b64decode(key)
                            key = self.private_key.decrypt(
                                key,
                                padding.OAEP(
                                    algorithm=hashes.SHA256(),
                                    label=None,
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                ),
                            )

                            public_key_share_client = cert.public_key()
                            encrypted_key = public_key_share_client.encrypt(
                                key,
                                padding.OAEP(
                                    algorithm=hashes.SHA256(),
                                    label=None,
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                ),
                            )
                            file_keys.append(encrypted_key)

                        file_keys = [base64.b64encode(k).decode() for k in file_keys]
                        print

                        return encrypt_message(
                            self.shared_key,
                            b"11R?" + mkpair(group_id, "||".join(file_keys).encode()),
                        )

                elif command == "11RR":
                    content = content.decode()
                    if content == "1":
                        print(
                            f"\n[+] Utilizador '{self.share_user_id}' adicionado ao grupo com sucesso!"
                        )
                        self.share_user_id = None

                elif command == "12R":
                    content = content.decode()
                    if content == "1":
                        print(
                            f"\n[+] Utilizador '{self.share_user_id}' removido do grupo com sucesso!"
                        )
                        self.share_user_id = None
                elif command == "13R":
                    file_id, certificados = unpair(content)
                    encrypted_keys_for_members = []

                    if not certificados:
                        print("Ficheiro adicionado ao grupo com sucesso!")
                        return b"Ignore"

                    certificados_list = certificados.decode().split("||")
                    for cert_pem in certificados_list:
                        cert = x509.load_pem_x509_certificate(cert_pem.encode())
                        public_key = cert.public_key()
                        encrypted_key = public_key.encrypt(
                            self.chave_criptografar,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None,
                            ),
                        )
                        encrypted_keys_for_members.append(encrypted_key)

                    keys_b64 = [
                        base64.b64encode(k).decode() for k in encrypted_keys_for_members
                    ]

                    return encrypt_message(
                        self.shared_key,
                        b"13R?" + mkpair(file_id, "||".join(keys_b64).encode()),
                    )

                elif command == "13RR":
                    content = content.decode()
                    print(f"[+] Ficheiro '{content}' adicionado ao grupo com sucesso!")

                elif command == "14R":
                    content = content.decode()
                    try:
                        print("\n[+] Lista de grupos:")
                        print("|", "-" * 80, "|")
                        for line in content.split("||"):
                            line = line.strip()
                            if not line or "--" not in line:
                                continue
                            id, nome = line.split("--", 1)
                            print(f"| Id: {id.ljust(38)} Nome: {nome.ljust(38)}   |")
                        print("|", "-" * 80, "|")

                    except Exception as e:
                        print(f"\n[ERROR] Falha a mostrar lista: {e}")

                elif command == "404":
                    print("[Erro]: " + content.decode())
                else:
                    print("\n[+] Mensagem desconhecida recebida do servidor.")

            display_welcome_banner(self.user_id)

            user_input = input("-> ")
            if user_input.strip().lower() in ["exit", "quit"]:
                return None
            elif user_input.strip().lower() == "help":
                os.system("cls" if os.name == "nt" else "clear")
                display_help()
                return b"Ignore"
            elif user_input.strip().lower() == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                return b"Ignore"

            command, args = user_input.split(" ", 1)

            if command == "add":
                if len(args.split()) != 1:
                    print("\n[ERRO] Comando inválido. Use 'add <file_path>'")

                file_path = args.strip()
                if not os.path.isfile(file_path):
                    print(f"\n[ERRO] Ficheiro '{file_path}' não encontrado.")
                    return b"Ignore"

                chave = Fernet.generate_key()
                fernet = Fernet(chave)
                with open(file_path, "rb") as file:
                    file_data = file.read()
                encrypted_data = fernet.encrypt(file_data)

                file_name = os.path.basename(file_path)

                file_encrypted = mkpair(file_name.encode(), encrypted_data)

                encrypted_key = self.public_key.encrypt(
                    chave,
                    padding.OAEP(
                        algorithm=hashes.SHA256(),
                        label=None,
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    ),
                )

                return encrypt_message(
                    self.shared_key, b"1?" + mkpair(encrypted_key, file_encrypted)
                )

            elif command == "read":
                if len(args.split()) != 1:
                    print("\n[ERRO] Comando inválido. Use 'read <file_id>'")
                    return b"Ignore"
                file_id = args.strip()
                return encrypt_message(self.shared_key, b"2?" + file_id.encode())

            elif command == "delete":
                if len(args.split()) != 1:
                    print("\n[ERRO] Comando inválido. Use 'delete <file_id>'")
                    return b"Ignore"
                file_id = args.strip()
                return encrypt_message(self.shared_key, b"3?" + file_id.encode())

            elif command == "share":
                if len(args.split()) != 3:
                    print(
                        "\n[ERRO] Comando inválido. Use 'share <file_id> <user_id> <permissions>'"
                    )
                    return b"Ignore"
                file_id, self.share_user_id, permissions = args.split()
                return encrypt_message(
                    self.shared_key,
                    b"4?"
                    + mkpair(
                        mkpair(file_id.encode(), self.share_user_id.encode()),
                        permissions.encode(),
                    ),
                )

            elif command == "revoke":
                if len(args.split()) != 2:
                    print("\n[ERRO] Comando inválido. Use 'revoke <file_id> <user_id>'")
                    return b"Ignore"
                file_id, user_id = args.split()
                return encrypt_message(
                    self.shared_key, b"5?" + mkpair(file_id.encode(), user_id.encode())
                )

            elif command == "list":
                parts = args.strip().split()

                if not parts:
                    print(
                        "\n[ERRO] Comando inválido. Use 'list -u <user-id>' ou 'list -g <group-id>'"
                    )
                    return b"Ignore"

                if parts[0] == "-g":
                    if len(parts) != 2:
                        print("\n[ERRO] Uso correto: 'list -g <group-id>'")
                        return b"Ignore"
                    return encrypt_message(self.shared_key, b"6?" + parts[1].encode())

                elif parts[0] == "-u":
                    if len(parts) != 1:
                        print("\n[ERRO] Uso correto: 'list -u'")
                        return b"Ignore"
                    return encrypt_message(self.shared_key, b"6?U")

                else:
                    print("\n[ERRO] Flag inválida. Use '-u' ou '-g'")
                    return b"Ignore"

            elif command == "replace":
                if len(args.split()) != 2:
                    print(
                        "\n[ERRO] Comando inválido. Use ' replace <file-id> <file-path>'"
                    )
                    return b"Ignore"

                file_id, file_path = args.split()

                if not os.path.isfile(file_path):
                    print(f"\n[ERRO] Ficheiro '{file_path}' não encontrado.")
                    return b"Ignore"

                return encrypt_message(
                    self.shared_key,
                    b"7?" + mkpair(file_id.encode(), file_path.encode()),
                )

            elif command == "details":
                parts = args.strip().split()
                if len(parts) > 1:
                    print("\n[ERRO] Comando inválido. Use 'details <file-id>'")
                    return b"Ignore"

                return encrypt_message(self.shared_key, b"8?" + parts[0].encode())

            elif command == "group":
                parts = args.strip().split()
                function = parts[0]
                details = parts[1:]
                if function not in [
                    "create",
                    "delete",
                    "add-user",
                    "delete-user",
                    "list",
                    "add",
                ]:
                    print(
                        "\n[ERRO] Comando inválido. Use 'group <create|delete|add-user|delete-user|list>'"
                    )
                    return b"Ignore"

                if function == "create":
                    if len(details) != 1:
                        print(
                            "\n[ERRO] Comando inválido. Use 'group create <group-name>'"
                        )
                        return b"Ignore"
                    group_name = details[0] if details else ""
                    if not group_name:
                        print("\n[ERRO] Nome do grupo não pode ser vazio.")
                        return b"Ignore"

                    return encrypt_message(self.shared_key, b"9?" + group_name.encode())

                elif function == "delete":
                    if len(details) != 1:
                        print(
                            "\n[ERRO] Comando inválido. Use 'group delete <group-id>'"
                        )
                        return b"Ignore"
                    group_id = details[0] if details else ""
                    if not group_id:
                        print("\n[ERRO] ID do grupo não pode ser vazio.")
                        return b"Ignore"

                    return encrypt_message(self.shared_key, b"10?" + group_id.encode())

                elif function == "add-user":
                    if len(details) != 3:
                        print(
                            "\n[ERRO] Comando inválido. Use 'group add-user <group-id> <user-id> <permissions>'"
                        )
                        return b"Ignore"

                    group_id, user_id, permissions = details
                    self.share_user_id = user_id

                    return encrypt_message(
                        self.shared_key,
                        b"11?"
                        + mkpair(
                            mkpair(group_id.encode(), user_id.encode()),
                            permissions.encode(),
                        ),
                    )

                elif function == "delete-user":
                    group_id, user_id = details
                    self.share_user_id = user_id

                    return encrypt_message(
                        self.shared_key,
                        b"12?" + mkpair(group_id.encode(), user_id.encode()),
                    )

                elif function == "add":
                    if len(details) != 2:
                        print(
                            "\n[ERRO] Comando inválido. Use 'group add <group-id> <file-path>'"
                        )
                        return b"Ignore"
                    group_id, file_path = details

                    if not os.path.isfile(file_path):
                        print(f"\n[ERRO] Ficheiro '{file_path}' não encontrado.")
                        return b"Ignore"

                    chave = Fernet.generate_key()
                    self.chave_criptografar = chave
                    fernet = Fernet(chave)
                    encrypted_data = fernet.encrypt(open(file_path, "rb").read())
                    file_name = os.path.basename(file_path)

                    encrypted_key = self.public_key.encrypt(
                        chave,
                        padding.OAEP(
                            algorithm=hashes.SHA256(),
                            label=None,
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        ),
                    )

                    return encrypt_message(
                        self.shared_key,
                        b"13?"
                        + mkpair(
                            mkpair(group_id.encode(), encrypted_key),
                            mkpair(file_name.encode(), encrypted_data),
                        ),
                    )

                elif function == "list":
                    if len(details) != 0:
                        print("\n[ERRO] Comando inválido. Use 'group list'")
                        return b"Ignore"
                    return encrypt_message(self.shared_key, b"14?1")
            else:
                print("\n[ERRO] Comando inválido.")
                return b"Ignore"

            return msg


async def tcp_echo_client(p12_file):
    try:
        client = Client(p12_file)
        reader, writer = await asyncio.open_connection("127.0.0.1", conn_port)
        print(f"[OK] Conectado ao servidor (porta {conn_port})")

        msg = await client.process()
        while msg:
            writer.write(msg)
            await writer.drain()

            data = await reader.read(max_msg_size)
            if not data:
                print("\n[ERRO] Nenhuma resposta recebida do servidor.")
                break

            msg = await client.process(data)

    except Exception as e:
        print(f"\n[ERRO] Conexão falhou: {e}")
    finally:
        if "writer" in locals():
            writer.close()
            await writer.wait_closed()
        print("\n[-] Conexão encerrada")


def run_client():
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <caminho_keystore.p12>")
        sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client(sys.argv[1]))


if __name__ == "__main__":
    conn_port = 7777
    run_client()

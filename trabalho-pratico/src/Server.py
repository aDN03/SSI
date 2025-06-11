import asyncio
import base64
import json
import os
import shutil
import tempfile

from assistant import (
    carregar_certificado,
    encrypt_message,
    generate_group_id,
    get_Data,
    guardar_certificado,
    mkpair,
    unpair,
    validate_certificate,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
    load_pem_public_key,
    pkcs12,
)

conn_cnt = 0
conn_port = 7777
max_msg_size = 9999
SERVER_P12 = "../.p12/VAULT_SERVER.p12"


# Parâmetros DH
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
pn = dh.DHParameterNumbers(p, g)
parameters = pn.parameters()


class VaultServer:
    def __init__(self, client_id):
        self.client_id = None
        self.msg_cnt = 0
        self.dh_public_client = None
        self.shared_key = None
        (
            self.cert,
            self.user_id,
            self.ca_name,
            self.rsa_private_key,
            self.rsa_public_key,
            self.not_valid_before,
            self.not_valid_after,
        ) = get_Data(SERVER_P12)
        self.dh_private_key = parameters.generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()
        self.share_file_id = None
        self.share_user_id = None
        self.group_id_add = None
        self.permissions = None

    async def process(self, msg):
        self.msg_cnt += 1

        if msg == b"Ignore":
            return b"IGNORE"

        if self.msg_cnt == 1:
            print("[+] A validar cliente...")
            self.dh_public_client = msg
            dh_public = self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            msg_send = mkpair(dh_public, msg)
            msg_send = self.rsa_private_key.sign(
                msg_send,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )

            msg_send = mkpair(dh_public, msg_send)
            msg_send = mkpair(msg_send, self.cert.public_bytes(Encoding.PEM))

            return msg_send

        elif self.msg_cnt == 2:
            signature, cert = unpair(msg)
            cert = x509.load_pem_x509_certificate(cert)
            subject_attrs = {attr.oid._name: attr.value for attr in cert.subject}
            self.client_id = subject_attrs.get("pseudonym", "UNKNOWN")
            guardar_certificado(cert, self.client_id)
            if not validate_certificate(cert):
                return encrypt_message(self.shared_key, b"404?Certificado invalido")
            public_key_client = cert.public_key()

            try:
                public_key_client.verify(
                    signature,
                    mkpair(
                        self.dh_public_client,
                        self.dh_public_key.public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        ),
                    ),
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )

                print("[OK] Assinatura válida!")
            except Exception as e:
                print("[ERROR] Falha na verificação da assinatura:", e)

            self.shared_key = self.dh_private_key.exchange(
                load_der_public_key(self.dh_public_client)
            )
            print("[OK] Chave compartilhada estabelecida com sucesso!")
            print("[OK] Cliente autenticado com sucesso!")
            os.makedirs(f"../VAULT_STORAGE/users/{self.client_id}", exist_ok=True)
            return b"IGNORE"

        elif self.msg_cnt > 2:
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

            if command == "1":
                encrypted_key, rest = unpair(content)
                file_name, encrypted_file = unpair(rest)
                file_name = file_name.decode()

                with open(
                    f"../VAULT_STORAGE/users/{self.client_id}/{file_name}", "wb"
                ) as f:
                    f.write(encrypted_file)

                caminho = f"../VAULT_STORAGE/users/{self.client_id}/permissions.json"
                id = 0
                files = []

                os.makedirs(os.path.dirname(caminho), exist_ok=True)
                if os.path.exists(caminho):
                    with open(caminho, "r", encoding="utf-8") as f:
                        files = json.load(f)
                        if files:
                            id_str = files[-1]["id"]
                            id = int(id_str.split("_")[2]) + 1

                if any(item.get("file_name") == file_name for item in files):
                    return encrypt_message(
                        self.shared_key, b"404?Ja existe um ficheiro com o mesmo nome"
                    )

                encoded_key = base64.b64encode(encrypted_key).decode()
                id = f"{self.client_id}_{id}"
                new_file = {
                    "id": id,
                    "file_name": file_name,
                    "encoded_key": encoded_key,
                    "permissions": [],
                }

                files.append(new_file)

                with open(caminho, "w", encoding="utf-8") as f:
                    json.dump(files, f, indent=4)

                return encrypt_message(self.shared_key, b"1R?" + f"{id}".encode())

            elif command == "2":
                content = content.decode()

                if content.split("_")[0] == "g":
                    pasta = content.rsplit("_", 1)[0]
                    caminho = f"../VAULT_STORAGE/groups/{pasta}/permissions.json"
                    if not os.path.exists(caminho):
                        return encrypt_message(
                            self.shared_key, b"404?Ficheiro nao encontrado"
                        )

                    with open(caminho, "r", encoding="utf-8") as f:
                        files = json.load(f)

                    for member in files["members"]:
                        if member[0] == self.client_id:
                            member_perm = member[1]

                    if self.client_id == files["owner"] or "R" in member_perm:
                        for file in files["files"]:
                            if file["id"] == content:
                                for permission in file["permissions"]:
                                    if permission[0] == self.client_id:
                                        file_name = file["file_name"]
                                        chave = permission[1]
                                        file_path = f"../VAULT_STORAGE/groups/{pasta}/{file_name}"
                                        if os.path.exists(file_path):

                                            with open(file_path, "rb") as f:
                                                file_data = f.read()
                                                return encrypt_message(
                                                    self.shared_key,
                                                    b"2R?"
                                                    + mkpair(
                                                        mkpair(
                                                            file_data, chave.encode()
                                                        ),
                                                        file_name.encode(),
                                                    ),
                                                )

                                        else:
                                            return encrypt_message(
                                                self.shared_key,
                                                b"404?Ficheiro nao encontrado",
                                            )
                    else:
                        return encrypt_message(
                            self.shared_key,
                            b"404?Nao possui permissao para ler o ficheiro",
                        )
                else:
                    owner_id = content.rsplit("_", 1)[0]
                    client_path = (
                        f"../VAULT_STORAGE/users/{self.client_id}/permissions.json"
                    )

                    with open(client_path, "r", encoding="utf-8") as f:
                        file_cli = json.load(f)

                    for item in file_cli:
                        if item["id"] == content:
                            if owner_id == self.client_id:
                                rw = None
                            else:
                                rw = item["permissions"][0]

                            if owner_id == self.client_id or "R" in rw:
                                file_name = item["file_name"]
                                pasta = content.rsplit("_", 1)[0]

                                caminho_arquivo = (
                                    f"../VAULT_STORAGE/users/{pasta}/{file_name}"
                                )

                                if os.path.exists(caminho_arquivo):
                                    with open(caminho_arquivo, "rb") as f:
                                        file_data = f.read()
                                else:
                                    return encrypt_message(
                                        self.shared_key,
                                        b"404?Ficheiro nao encontrado",
                                    )

                                chave = item["encoded_key"]

                                return encrypt_message(
                                    self.shared_key,
                                    b"2R?"
                                    + mkpair(
                                        mkpair(file_data, chave.encode()),
                                        file_name.encode(),
                                    ),
                                )

                            else:
                                return encrypt_message(
                                    self.shared_key,
                                    b"404?Nao tem permissoes para ler o ficheiro",
                                )

            elif command == "3":
                content = content.decode()
                if content.split("_")[0] == "g":
                    pasta = content.rsplit("_", 1)[0]
                    caminho = f"../VAULT_STORAGE/groups/{pasta}/permissions.json"
                    if not os.path.exists(caminho):
                        return encrypt_message(
                            self.shared_key, b"404?Ficheiro nao encontrado"
                        )

                    with open(caminho, "r", encoding="utf-8") as f:
                        files = json.load(f)

                    for member in files["members"]:
                        if member[0] == self.client_id:
                            member_perm = member[1]

                    if "W" in member_perm or self.client_id == files["owner"]:
                        for file in files["files"]:
                            if file["id"] == content:
                                file_name = file["file_name"]
                                file_path = (
                                    f"../VAULT_STORAGE/groups/{pasta}/{file_name}"
                                )

                                files["files"] = [
                                    file
                                    for file in files["files"]
                                    if file["id"] != content
                                ]
                                with open(caminho, "w", encoding="utf-8") as f:
                                    json.dump(files, f, indent=4)

                                if os.path.exists(file_path):
                                    os.remove(file_path)
                                    return encrypt_message(
                                        self.shared_key,
                                        b"3R?" + str(file_name).encode(),
                                    )
                                else:
                                    return encrypt_message(
                                        self.shared_key,
                                        b"404?Ficheiro nao encontrado",
                                    )
                    else:
                        return encrypt_message(
                            self.shared_key,
                            b"404?Nao possui permissao para apagar o ficheiro",
                        )
                else:
                    owner_id = content.rsplit("_", 1)[0]
                    caminho = f"../VAULT_STORAGE/users/{owner_id}/permissions.json"
                    client_path = (
                        f"../VAULT_STORAGE/users/{self.client_id}/permissions.json"
                    )

                    with open(client_path, "r", encoding="utf-8") as f:
                        file_cli = json.load(f)

                    for item in file_cli:
                        id_str = item["id"]
                        if id_str == content:
                            rw = item["permissions"][0]

                    if owner_id == self.client_id or "W" in rw:
                        if not os.path.exists(caminho):
                            return encrypt_message(
                                self.shared_key, b"404?Ficheiro nao encontrado"
                            )

                        encontrado = False
                        with open(caminho, "r", encoding="utf-8") as f:
                            files = json.load(f)

                        novos_files = []
                        perms = []
                        for item in files:
                            id_str = item["id"]
                            if id_str == content:
                                encontrado = True
                                file_name = item["file_name"]
                                perms = item["permissions"]
                                caminho_arquivo = (
                                    f"../VAULT_STORAGE/users/{owner_id}/{file_name}"
                                )
                                if os.path.exists(caminho_arquivo):
                                    os.remove(caminho_arquivo)
                            else:
                                novos_files.append(item)

                            if perms != []:
                                for permission in perms:
                                    user = permission[1]
                                    path = f"../VAULT_STORAGE/users/{user}/permissions.json"

                                    if os.path.exists(path):
                                        with open(path, "r", encoding="utf-8") as f:
                                            file_perms = json.load(f)

                                        if (
                                            len(file_perms) == 1
                                            and file_perms[0].get("id") == content
                                        ):
                                            os.remove(path)

                                        else:
                                            new_file_perms = [
                                                perm
                                                for perm in file_perms
                                                if perm.get("id") != content
                                            ]

                                            if len(new_file_perms) != len(file_perms):
                                                with open(
                                                    path, "w", encoding="utf-8"
                                                ) as f:
                                                    json.dump(
                                                        new_file_perms, f, indent=4
                                                    )

                        if encontrado:
                            if novos_files:
                                with open(caminho, "w", encoding="utf-8") as f:
                                    json.dump(novos_files, f, indent=4)
                            else:

                                os.remove(caminho)

                                new_file_perms = [
                                    perm
                                    for perm in file_perms
                                    if perm.get("id") != content
                                ]

                            return encrypt_message(
                                self.shared_key, b"3R?" + str(file_name).encode()
                            )

                        else:

                            return encrypt_message(
                                self.shared_key, b"404?Ficheiro nao encontrado"
                            )
                    else:
                        return encrypt_message(
                            self.shared_key,
                            b"404?Nao tem permissoes para apagar o ficheiro",
                        )

            elif command == "4":
                rest, permissions = unpair(content)
                file_id, user_id = unpair(rest)
                file_id = file_id.decode()
                user_id = user_id.decode()
                self.permissions = permissions.decode()
                if self.permissions not in ["W", "R", "WR", "RW"]:
                    return encrypt_message(
                        self.shared_key, b"404?Valor de Permissao Incorreto"
                    )

                self.share_file_id = file_id
                self.share_user_id = user_id
                if os.path.exists(f"../VAULT_STORAGE/users/{user_id}/permissions.json"):
                    with open(
                        f"../VAULT_STORAGE/users/{user_id}/permissions.json",
                        "r",
                        encoding="utf-8",
                    ) as f:
                        permissoes = json.load(f)
                    for item in permissoes:
                        id_str = item["id"]
                        if id_str == file_id:
                            if set(self.permissions).issubset(
                                set(item["permissions"][0])
                            ):
                                return encrypt_message(
                                    self.shared_key,
                                    b"404?Ja existe essa permissao para o utilizador",
                                )
                            else:
                                novas_permissoes = list(
                                    set(item["permissions"]) | set(self.permissions)
                                )
                                item["permissions"][0] = "".join(novas_permissoes)
                                with open(
                                    f"../VAULT_STORAGE/users/{user_id}/permissions.json",
                                    "w",
                                    encoding="utf-8",
                                ) as f:
                                    json.dump(permissoes, f, indent=4)
                            return encrypt_message(
                                self.shared_key, b"404?Permissao adicionada com sucesso"
                            )

                caminho = f"../VAULT_STORAGE/users/{self.client_id}/permissions.json"

                try:
                    encontrado = False
                    with open(caminho, "r", encoding="utf-8") as f:
                        files = json.load(f)

                    for item in files:
                        id_str = item["id"]
                        if id_str != file_id:
                            continue

                        encontrado = True
                        file_name = item["file_name"]
                        chave = item["encoded_key"]

                        cert = carregar_certificado(user_id)
                        if not cert:
                            return encrypt_message(
                                self.shared_key, b"404?Certificado nao encontrado"
                            )

                        return encrypt_message(
                            self.shared_key,
                            b"4R?"
                            + mkpair(chave.encode(), cert.public_bytes(Encoding.PEM)),
                        )

                    if not encontrado:
                        return encrypt_message(
                            self.shared_key, b"404?Ficheiro nao encontrado"
                        )

                except FileNotFoundError:
                    return encrypt_message(
                        self.shared_key, b"404?Ficheiro nao encontrado"
                    )

            elif command == "4R":
                encoded_key = base64.b64encode(content).decode()
                file_id = self.share_file_id
                user_id = self.share_user_id
                file_name = None

                caminho_emissor = (
                    f"../VAULT_STORAGE/users/{self.client_id}/permissions.json"
                )

                if not os.path.exists(caminho_emissor):
                    return encrypt_message(
                        self.shared_key, b"404?Ficheiro nao encontrado"
                    )

                with open(caminho_emissor, "r", encoding="utf-8") as f:
                    permissoes_emissor = json.load(f)

                for item in permissoes_emissor:
                    id_str = item["id"]
                    if id_str == file_id:
                        file_name = item["file_name"]
                        permissions = item["permissions"]
                        permissions.append([self.permissions, user_id])
                        break

                if file_name is None:
                    return encrypt_message(
                        self.shared_key, b"404?Ficheiro nao encontrado"
                    )

                with open(caminho_emissor, "w", encoding="utf-8") as f:
                    json.dump(permissoes_emissor, f, indent=4)

                caminho_destino = f"../VAULT_STORAGE/users/{user_id}/permissions.json"
                os.makedirs(os.path.dirname(caminho_destino), exist_ok=True)

                permissoes_destino = []
                if os.path.exists(caminho_destino):
                    with open(caminho_destino, "r", encoding="utf-8") as f:
                        permissoes_destino = json.load(f)

                nova_entrada = {
                    "id": self.share_file_id,
                    "file_name": file_name,
                    "encoded_key": encoded_key,
                    "permissions": [self.permissions],
                }
                self.permissions = None

                permissoes_destino.append(nova_entrada)

                with open(caminho_destino, "w", encoding="utf-8") as f:
                    json.dump(permissoes_destino, f, indent=4)

                return encrypt_message(self.shared_key, b"4RR?1")

            elif command == "5":
                file_id, user_id = unpair(content)
                file_id = file_id.decode()
                user_id = user_id.decode()

                if file_id.rsplit("_", 1)[0] != self.client_id:
                    return encrypt_message(
                        self.shared_key, b"404?Ficheiro nao encontrado"
                    )

                caminho_emissor = (
                    f"../VAULT_STORAGE/users/{self.client_id}/permissions.json"
                )
                if not os.path.exists(caminho_emissor):
                    return encrypt_message(
                        self.shared_key, b"404?Caminho do emissor nao existe."
                    )

                if user_id == (file_id.split("_")[0] + "_" + file_id.split("_")[1]):
                    return encrypt_message(
                        self.shared_key,
                        b"404?Nao e possivel apagar as proprias permissoes",
                    )

                with open(caminho_emissor, "r", encoding="utf-8") as f:
                    permissoes_emissor = json.load(f)

                existe = any(item["id"] == file_id for item in permissoes_emissor)
                if not existe:
                    return encrypt_message(
                        self.shared_key, b"404?ID do ficheiro nao encontrado"
                    )

                file_found = False
                updated = False

                for item in permissoes_emissor:
                    if item["id"] == file_id:
                        file_found = True
                        original_len = len(item["permissions"])
                        item["permissions"] = [
                            perm for perm in item["permissions"] if perm[1] != user_id
                        ]
                        if len(item["permissions"]) != original_len:
                            updated = True
                        break

                if not file_found:
                    return encrypt_message(
                        self.shared_key, b"404?ID do ficheiro nao encontrado"
                    )

                if updated:
                    with open(caminho_emissor, "w", encoding="utf-8") as f:
                        json.dump(permissoes_emissor, f, indent=4)
                else:
                    return encrypt_message(
                        self.shared_key, b"404?Permissao do utilizador nao encontrada"
                    )

                caminho_destino = f"../VAULT_STORAGE/users/{user_id}/permissions.json"
                if not os.path.exists(caminho_destino):
                    return encrypt_message(
                        self.shared_key, b"404?Caminho do destinatario nao existe."
                    )

                with open(caminho_destino, "r", encoding="utf-8") as f:
                    permissoes_destino = json.load(f)

                permissoes_destino = [
                    item for item in permissoes_destino if item["id"] != file_id
                ]

                if permissoes_destino:
                    print("[INFO] Permissões restantes no destinatário.")
                    with open(caminho_destino, "w", encoding="utf-8") as f:
                        json.dump(permissoes_destino, f, indent=4)
                else:
                    os.remove(caminho_destino)

                return encrypt_message(self.shared_key, b"5R?1")

            elif command == "6":
                if content.decode() == "U":
                    caminho = (
                        f"../VAULT_STORAGE/users/{self.client_id}/permissions.json"
                    )
                    option, user_id = unpair(content)
                    option = option.decode()
                    user_id = user_id.decode()

                    try:
                        if not os.path.exists(caminho):
                            return encrypt_message(
                                self.shared_key, b"404?Caminho do emissor nao existe."
                            )

                        with open(caminho, "r", encoding="utf-8") as f:
                            permissoes = json.load(f)

                        resposta = ""
                        for item in permissoes:
                            file_id = item["id"]
                            file_name = item["file_name"]
                            resposta += f"{file_id}--{file_name};"

                        return encrypt_message(
                            self.shared_key, b"6R?" + resposta.encode()
                        )

                    except Exception as e:
                        return encrypt_message(
                            self.shared_key, b"404?Erro ao ler permissoes"
                        )
                else:
                    group_id = content.decode()
                    caminho = f"../VAULT_STORAGE/groups/{group_id}/permissions.json"
                    if not os.path.exists(caminho):
                        return encrypt_message(
                            self.shared_key, b"404?Grupo nao encontrado"
                        )
                    with open(caminho, "r", encoding="utf-8") as f:
                        group = json.load(f)
                    resposta = ""
                    for file in group["files"]:
                        file_id = file["id"]
                        file_name = file["file_name"]
                        resposta += f"{file_id}--{file_name};"
                    return encrypt_message(self.shared_key, b"6R?" + resposta.encode())

            elif command == "7":
                file_id, file_path = unpair(content)
                file_id = file_id.decode()
                file_path = file_path.decode()

                if file_id.split("_")[0] == "g":
                    owner_id = file_id.rsplit("_", 1)[0]
                    caminho = f"../VAULT_STORAGE/groups/{owner_id}/permissions.json"
                    if not os.path.exists(caminho):
                        return encrypt_message(
                            self.shared_key, b"404?Caminho do emissor nao existe."
                        )

                    with open(caminho, "r", encoding="utf-8") as f:
                        files = json.load(f)
                    encontrado = False
                    member_perm = None
                    for member in files["members"]:
                        if member[0] == self.client_id:
                            member_perm = member[1]
                            break
                    if files["owner"] == self.client_id or "W" in member_perm:
                        for file in files["files"]:
                            if file["id"] == file_id:
                                for permission in file["permissions"]:
                                    if permission[0] == self.client_id:
                                        encoded_key = permission[1]
                                        return encrypt_message(
                                            self.shared_key,
                                            b"7R?"
                                            + mkpair(
                                                mkpair(
                                                    file_id.encode(), file_path.encode()
                                                ),
                                                encoded_key.encode(),
                                            ),
                                        )
                    if not encontrado:
                        return encrypt_message(
                            self.shared_key, b"404?ID do ficheiro nao encontrado"
                        )

                else:

                    owner_id = file_id.rsplit("_", 1)[0]

                    caminho = (
                        f"../VAULT_STORAGE/users/{self.client_id}/permissions.json"
                    )

                    if os.path.exists(caminho):
                        with open(caminho, "r", encoding="utf-8") as f:
                            files = json.load(f)
                    else:
                        return encrypt_message(
                            self.shared_key, b"404?Caminho do emissor nao existe."
                        )

                    encontrado = False
                    for item in files:
                        id_str = item["id"]
                        if id_str == file_id:
                            if item["permissions"] != []:
                                rw = item["permissions"][0]
                            encontrado = True

                    if not encontrado:
                        return encrypt_message(
                            self.shared_key, b"404?ID do ficheiro nao encontrado"
                        )

                    if owner_id == self.client_id or "W" in rw:
                        for item in files:
                            if id_str == item["id"]:
                                encoded_key = item["encoded_key"]
                                return encrypt_message(
                                    self.shared_key,
                                    b"7R?"
                                    + mkpair(
                                        mkpair(file_id.encode(), file_path.encode()),
                                        encoded_key.encode(),
                                    ),
                                )
                        return encrypt_message(
                            self.shared_key, b"404?ID do ficheiro nao encontrado"
                        )
                    else:
                        return encrypt_message(
                            self.shared_key,
                            b"404?Nao tem permissoes para trocar o ficheiro",
                        )

            elif command == "7R":
                file_id, rest = unpair(content)
                file_name, encrypted_file = unpair(rest)
                file_id = file_id.decode()
                file_name = file_name.decode()
                replace_name = None

                if file_id.split("_")[0] == "g":
                    owner_id = file_id.rsplit("_", 1)[0]
                    caminho = f"../VAULT_STORAGE/groups/{owner_id}/permissions.json"

                    with open(caminho, "r", encoding="utf-8") as f:
                        files = json.load(f)

                    replace_name = None
                    for file in files["files"]:
                        if file["id"] == file_id:
                            replace_name = file["file_name"]
                            file["file_name"] = file_name
                            caminho_arquivo = (
                                f"../VAULT_STORAGE/groups/{owner_id}/{replace_name}"
                            )
                            if os.path.exists(caminho_arquivo):
                                os.remove(caminho_arquivo)
                            break

                    with open(caminho, "w", encoding="utf-8") as f:
                        json.dump(files, f, indent=4)

                    file_path = f"../VAULT_STORAGE/groups/{owner_id}/{file_name}"
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    with open(file_path, "wb") as f:
                        f.write(encrypted_file)

                    return encrypt_message(
                        self.shared_key, b"7RR?" + f"{file_id}".encode()
                    )

                else:
                    owner_id = file_id.rsplit("_", 1)[0]
                    caminho = f"../VAULT_STORAGE/users/{owner_id}/permissions.json"

                    found = False

                    if os.path.exists(caminho):
                        with open(caminho, "r", encoding="utf-8") as f:
                            files = json.load(f)
                    else:
                        return encrypt_message(
                            self.shared_key, b"404?Caminho do emissor nao existe."
                        )

                    for item in files:
                        if item["id"] == file_id:
                            perms = item["permissions"]
                            found = True

                            for permission in perms:
                                user = permission[1]
                                path = f"../VAULT_STORAGE/users/{user}/permissions.json"

                                if os.path.exists(path):
                                    with open(path, "r", encoding="utf-8") as f:
                                        perm_file = json.load(f)

                                    for entry in perm_file:
                                        if entry["id"] == item["id"]:
                                            entry["file_name"] = file_name

                                    with open(path, "w", encoding="utf-8") as f:
                                        json.dump(perm_file, f, indent=4)

                            file_path = f"../VAULT_STORAGE/users/{owner_id}/{file_name}"
                            os.makedirs(os.path.dirname(file_path), exist_ok=True)
                            with open(file_path, "wb") as f:
                                f.write(encrypted_file)

                            if file_name != item["file_name"]:
                                replace_name = item["file_name"]
                                delete_path = (
                                    f"../VAULT_STORAGE/users/{owner_id}/{replace_name}"
                                )
                                item["file_name"] = file_name
                                if os.path.exists(delete_path):
                                    os.remove(delete_path)

                                with open(caminho, "w", encoding="utf-8") as f:
                                    json.dump(files, f, indent=4)

                            if not found:
                                return encrypt_message(
                                    self.shared_key,
                                    b"404?ID do ficheiro nao encontrado",
                                )

                            return encrypt_message(
                                self.shared_key, b"7RR?" + f"{file_id}".encode()
                            )

            elif command == "8":
                file_id = content.decode()

                if file_id.split("_")[0] == "g":
                    pasta = file_id.rsplit("_", 1)[0]
                    caminho = f"../VAULT_STORAGE/groups/{pasta}/permissions.json"
                    if not os.path.exists(caminho):
                        return encrypt_message(
                            self.shared_key, b"404?Ficheiro nao encontrado"
                        )
                    try:
                        with open(caminho, "r", encoding="utf-8") as f:
                            files = json.load(f)

                        user_perms = []

                        for file in files["files"]:
                            if file["id"] == file_id:
                                try:
                                    file_name = file["file_name"]
                                    perms = file["permissions"]
                                    for perm in perms:
                                        user_perms.append(perm[0])

                                except Exception as e:
                                    return encrypt_message(
                                        self.shared_key, b"404?Algum erro ocorreu"
                                    )
                        full_path = f"../VAULT_STORAGE/groups/{pasta}/{file_name}"
                        if os.path.isfile(full_path):
                            file_size = os.path.getsize(full_path)
                        else:
                            0

                        resposta = f"{file_name};{user_perms};{file_size}"
                        return encrypt_message(
                            self.shared_key, b"8RG?" + resposta.encode()
                        )
                    except FileNotFoundError:
                        return encrypt_message(
                            self.shared_key, b"404? O Ficheiro nao existe"
                        )
                else:
                    owner_id = file_id.split("_")[0] + "_" + file_id.split("_")[1]
                    caminho = f"../VAULT_STORAGE/users/{owner_id}/permissions.json"

                    try:
                        with open(caminho, "r", encoding="utf-8") as f:
                            files = json.load(f)

                        resposta = "[ERRO] ID não encontrado"
                        user_permissions_info = []

                        for item in files:
                            if item["id"] == file_id:
                                try:
                                    file_name = item["file_name"]
                                    perms = item["permissions"]
                                    file_path = f"{owner_id}/{file_name}"

                                    if owner_id == self.client_id:
                                        for uid in perms:
                                            user = uid[1]
                                            path = f"../VAULT_STORAGE/users/{user}/permissions.json"
                                            with open(path, "r", encoding="utf-8") as f:
                                                perm_file = json.load(f)

                                            user_perm = "none"
                                            for entry in perm_file:
                                                if entry["id"] == file_id:
                                                    user_perm = entry["permissions"]
                                                    break

                                            user_permissions_info.append(
                                                f"{user}:{user_perm}"
                                            )

                                        permissions_str = ",".join(
                                            user_permissions_info
                                        )

                                    else:
                                        path = f"../VAULT_STORAGE/users/{self.client_id}/permissions.json"
                                        with open(path, "r", encoding="utf-8") as f:
                                            perm_file = json.load(f)

                                        user_perm = "none"
                                        for entry in perm_file:
                                            if entry["id"] == file_id:
                                                user_perm = entry["permissions"]
                                                break

                                        permissions_str = f"{user_perm}"

                                    full_path = (
                                        f"../VAULT_STORAGE/users/{owner_id}/{file_name}"
                                    )
                                    if os.path.isfile(full_path):
                                        file_size = os.path.getsize(full_path)
                                    else:
                                        0

                                    resposta = f"{owner_id};{file_name};{permissions_str};{file_size}"
                                    return encrypt_message(
                                        self.shared_key, b"8R?" + resposta.encode()
                                    )

                                except Exception as e:
                                    return encrypt_message(
                                        self.shared_key, b"404?Algum erro ocorreu"
                                    )

                    except FileNotFoundError:
                        return encrypt_message(
                            self.shared_key, b"404? O Ficheiro nao existe"
                        )

            elif command == "9":
                group_name = content.decode()
                group_id = generate_group_id()
                caminho = f"../VAULT_STORAGE/groups/{group_id}"
                if not os.path.exists(caminho):
                    os.makedirs(caminho)
                    with open(f"{caminho}/permissions.json", "w") as f:
                        grupo = {
                            "id": group_id,
                            "name": group_name,
                            "owner": self.client_id,
                            "members": [],
                            "files": [],
                        }
                        json.dump(grupo, f, indent=4)

                caminho = f"../VAULT_STORAGE/groups"
                ficheiro = f"{caminho}/groups.json"

                if os.path.exists(ficheiro):
                    with open(ficheiro, "r") as f:
                        groups = json.load(f)
                else:
                    groups = []

                for member in groups:
                    if member["member"] == self.client_id:
                        if group_id not in member["groups"]:
                            member["groups"].append(group_id)
                        break
                else:
                    groups.append({"member": self.client_id, "groups": [group_id]})

                with open(ficheiro, "w") as f:
                    json.dump(groups, f, indent=4)

                    return encrypt_message(self.shared_key, b"9R?" + group_id.encode())

            elif command == "10":
                group_id = content.decode()
                caminho = f"../VAULT_STORAGE/groups/{group_id}/permissions.json"
                if os.path.exists(caminho):
                    with open(caminho, "r") as f:
                        grupo = json.load(f)
                        if grupo["owner"] == self.client_id:
                            caminho = f"../VAULT_STORAGE/groups/{group_id}"
                            shutil.rmtree(caminho)

                            caminho = f"../VAULT_STORAGE/groups/groups.json"
                            with open(caminho, "r") as f:
                                groups = json.load(f)
                            for member in groups:
                                if group_id in member["groups"]:
                                    member["groups"].remove(group_id)

                            with open(caminho, "w") as f:
                                json.dump(groups, f, indent=4)

                            return encrypt_message(
                                self.shared_key, b"10R?" + group_id.encode()
                            )

                        else:
                            return encrypt_message(
                                self.shared_key,
                                b"404?Nao tem permissao para apagar o grupo",
                            )

                else:
                    return encrypt_message(self.shared_key, b"404?Grupo nao encontrado")

            elif command == "11":
                rest, permission = unpair(content)
                group_id, user_id = unpair(rest)
                group_id = group_id.decode()
                user_id = user_id.decode()
                self.share_user_id = user_id
                permission = permission.decode()

                caminho = f"../VAULT_STORAGE/groups/{group_id}/permissions.json"
                if os.path.exists(caminho):
                    with open(caminho, "r") as f:
                        grupo = json.load(f)
                else:
                    return encrypt_message(self.shared_key, b"404?Grupo nao encontrado")

                if grupo["owner"] != self.client_id:
                    return encrypt_message(self.shared_key, b"404?Permissao negada")

                caminho_user = f"../VAULT_STORAGE/metadata/certs/{user_id}.crt"
                if not os.path.isfile(caminho_user):
                    return encrypt_message(
                        self.shared_key, b"404?Utilizador nao encontrado"
                    )

                if permission not in ["R", "W", "RW", "WR"]:
                    return encrypt_message(
                        self.shared_key, b"404?Valor de Permissao Incorreto"
                    )

                if grupo["owner"] == user_id:
                    return encrypt_message(
                        self.shared_key, b"404?Nao pode adicionar voce proprio"
                    )

                membros = grupo["members"]
                par_existente = next((m for m in membros if m[0] == user_id), None)

                if par_existente is None:
                    membros.append([user_id, permission])

                    file_keys = []
                    for file in grupo["files"]:
                        if file["permissions"] != []:
                            for permission in file["permissions"]:
                                if permission[0] == self.client_id:
                                    file_keys.append(permission[1])
                                    break
                else:
                    permissao_atual = par_existente[1]

                    if set(permission).issubset(set(permissao_atual)):
                        return encrypt_message(
                            self.shared_key,
                            b"404?Ja existe essa permissao para o utilizador",
                        )
                    else:
                        novas_permissoes = "".join(
                            sorted(set(permissao_atual) | set(permission))
                        )
                        grupo["members"] = [
                            [uid, novas_permissoes if uid == user_id else perm]
                            for uid, perm in membros
                        ]

                with open(caminho, "w") as f:
                    json.dump(grupo, f, indent=2)

                if par_existente is None:
                    groups_path = "../VAULT_STORAGE/groups/groups.json"
                    if os.path.exists(groups_path):
                        with open(groups_path, "r") as f:
                            groups = json.load(f)
                    else:
                        groups = []

                    encontrado = False
                    for member in groups:
                        if member["member"] == user_id:
                            encontrado = True
                            if group_id not in member["groups"]:
                                member["groups"].append(group_id)
                            break

                    if not encontrado:
                        groups.append({"member": user_id, "groups": [group_id]})

                    with open(groups_path, "w") as f:
                        json.dump(groups, f, indent=4)

                if file_keys:
                    cert = carregar_certificado(user_id)
                    if not cert:
                        return encrypt_message(
                            self.shared_key, b"404?Utilizador nao encontrado"
                        )
                    return encrypt_message(
                        self.shared_key,
                        b"11R?"
                        + mkpair(
                            mkpair(
                                group_id.encode(),
                                cert.public_bytes(Encoding.PEM),
                            ),
                            "||".join(file_keys).encode(),
                        ),
                    )

                else:
                    return encrypt_message(self.shared_key, b"11R?1")

            elif command == "11R":
                group_id, keys = unpair(content)
                group_id = group_id.decode()
                keys = keys.decode().split("||")
                caminho = f"../VAULT_STORAGE/groups/{group_id}/permissions.json"
                with open(caminho, "r") as f:
                    grupo = json.load(f)
                for i, file in enumerate(grupo["files"]):
                    file["permissions"].append([self.share_user_id, keys[i]])

                with open(caminho, "w") as f:
                    json.dump(grupo, f, indent=4)

                self.share_user_id = None

                return encrypt_message(self.shared_key, b"11RR?1")

            elif command == "12":
                group_id, user_id = unpair(content)
                group_id = group_id.decode()
                user_id = user_id.decode()
                caminho = f"../VAULT_STORAGE/groups/{group_id}/permissions.json"
                if os.path.exists(caminho):
                    with open(caminho, "r") as f:
                        grupo = json.load(f)
                        if grupo["owner"] == user_id:
                            return encrypt_message(
                                self.shared_key,
                                b"404?Nao e possivel remover o proprio utilizador",
                            )

                        if grupo["owner"] == self.client_id:

                            for member in grupo["members"]:
                                if member[0] == user_id:
                                    grupo["members"].remove(member)
                                    break
                            for file in grupo["files"]:
                                for permission in file["permissions"]:
                                    if permission[0] == user_id:
                                        file["permissions"].remove(permission)

                            with open(caminho, "w") as f:
                                json.dump(grupo, f, indent=4)

                            return encrypt_message(self.shared_key, b"12R?1")
                        else:
                            return encrypt_message(
                                self.shared_key,
                                b"404?Nao tem permissao para remover o utilizador",
                            )
                else:
                    return encrypt_message(self.shared_key, b"404?Grupo nao encontrado")

            elif command == "13":
                parte_0, parte_1 = unpair(content)
                group_id, encrypted_key = unpair(parte_0)
                file_name, encrypted_file = unpair(parte_1)
                self.group_id_add = group_id.decode()
                file_name = file_name.decode()

                caminho = (
                    f"../VAULT_STORAGE/groups/{self.group_id_add}/permissions.json"
                )
                if not os.path.exists(caminho):
                    return encrypt_message(self.shared_key, b"404?Grupo nao encontrado")
                os.makedirs(os.path.dirname(caminho), exist_ok=True)

                if os.path.exists(caminho):
                    with open(caminho, "r", encoding="utf-8") as f:
                        group_data = json.load(f)

                certificados_membros = []
                members = group_data["members"]
                is_owner = self.client_id == group_data["owner"]

                has_write_perm = any(
                    m[0] == self.client_id and "W" in m[1]
                    for m in group_data["members"]
                )

                if not (is_owner or has_write_perm):
                    return encrypt_message(
                        self.shared_key,
                        b"404?Nao tem permissao para adicionar o ficheiro ao grupo",
                    )

                for f in group_data["files"]:
                    if f["file_name"] == file_name:
                        return encrypt_message(
                            self.shared_key,
                            b"404?Ja existe um ficheiro no cofre com o mesmo nome",
                        )

                for membro in members:
                    cert = carregar_certificado(membro[0])
                    if cert:
                        certificados_membros.append(cert.public_bytes(Encoding.PEM))

                cert = carregar_certificado(group_data["owner"])
                certificados_membros.append(cert.public_bytes(Encoding.PEM))

                if group_data["files"]:
                    last_file_id = group_data["files"][-1]["id"]
                    last_number = int(last_file_id.split("_")[-1])
                    new_number = last_number + 1
                else:
                    new_number = 0

                file_id = f"{self.group_id_add}_{new_number}"

                file_path = f"../VAULT_STORAGE/groups/{self.group_id_add}/{file_name}"
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, "wb") as f:
                    f.write(encrypted_file)

                new_file_entry = {
                    "id": file_id,
                    "file_name": file_name,
                    "permissions": [],
                }

                group_data["files"].append(new_file_entry)

                with open(caminho, "w", encoding="utf-8") as f:
                    json.dump(group_data, f, indent=4)

                return encrypt_message(
                    self.shared_key,
                    b"13R?"
                    + mkpair(
                        file_id.encode(),
                        "||".join(
                            cert.decode() for cert in certificados_membros
                        ).encode(),
                    ),
                )

            elif command == "13R":
                file_id, payload = unpair(content)
                file_id = file_id.decode()

                all_keys_b64 = payload.decode().split("||")
                encrypted_keys_for_members = [base64.b64decode(k) for k in all_keys_b64]
                caminho = (
                    f"../VAULT_STORAGE/groups/{self.group_id_add}/permissions.json"
                )

                with open(caminho, "r", encoding="utf-8") as f:
                    group_data = json.load(f)

                members = group_data["members"]
                files = group_data["files"]
                ultimo_ficheiro = files[-1]
                permissions = ultimo_ficheiro["permissions"]

                for i, user_id in enumerate(members):
                    chave_cifrada = encrypted_keys_for_members[i]
                    chave_cifrada_b64 = base64.b64encode(chave_cifrada).decode()
                    permissions.append([user_id[0], chave_cifrada_b64])

                chave_cifrada = encrypted_keys_for_members[-1]
                chave_cifrada_b64 = base64.b64encode(chave_cifrada).decode()
                permissions.append([group_data["owner"], chave_cifrada_b64])

                ultimo_ficheiro["permissions"] = permissions

                with open(caminho, "w", encoding="utf-8") as f:
                    json.dump(group_data, f, indent=4)

                return encrypt_message(self.shared_key, f"13RR?{file_id}".encode())

            elif command == "14":
                caminho = "../VAULT_STORAGE/groups/groups.json"
                groupos = []

                if os.path.exists(caminho):
                    with open(caminho, "r") as f:
                        grupo = json.load(f)
                        for member in grupo:
                            if member["member"] == self.client_id:
                                groupos = member["groups"]
                                break

                    if groupos:
                        grupos_enviar = []
                        for group in groupos:
                            caminho = (
                                f"../VAULT_STORAGE/groups/{group}/permissions.json"
                            )
                            with open(caminho, "r") as f:
                                grupo = json.load(f)
                                grupos_enviar.append(f"{grupo['id']}--{grupo['name']}")

                        return encrypt_message(
                            self.shared_key, b"14R?" + "||".join(grupos_enviar).encode()
                        )
                    else:
                        return encrypt_message(
                            self.shared_key, b"404R?Sem grupos associados"
                        )
                else:
                    return encrypt_message(self.shared_key, b"404?Nao tem grupos")

            return b"IGNORE"


# ====================== CONEXÕES ======================
async def handle_client(reader, writer):
    """Gerencia conexão com cliente."""
    global conn_cnt
    conn_cnt += 1
    client_id = conn_cnt
    addr = writer.get_extra_info("peername")

    print(f"\n[+] Nova conexão: {addr} (ID: {client_id})")
    vault = VaultServer(client_id)

    try:
        while True:
            data = await reader.read(max_msg_size)
            if not data or data == b"\n":
                break

            response = await vault.process(data)
            if response:
                writer.write(response)
                await writer.drain()
            else:
                break

    except Exception as e:
        print(f"[!] Erro com cliente {client_id}: {e}")
    finally:
        if writer and not writer.is_closing():
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                print(f"[WARN] Erro ao fechar conexão: {e}")


# ====================== INICIAR SERVIDOR ======================
def run_server():
    """Inicia o servidor sem TLS."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        server = loop.run_until_complete(
            asyncio.start_server(handle_client, "0.0.0.0", conn_port)
        )
        print(f"\n[+] Servidor iniciado na porta {conn_port}")
        print("    Aguardando conexões (Ctrl+C para parar)...")
        loop.run_forever()

    except KeyboardInterrupt:
        print("\n[!] Servidor encerrando...")
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()


# ====================== MAIN ======================
if __name__ == "__main__":
    conn_cnt = 0
    run_server()

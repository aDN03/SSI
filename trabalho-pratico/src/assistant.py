import asyncio
import os
import random
import string
import sys
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa  # Importando rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
    pkcs12,
)


def get_Data(p12_file):
    try:
        with open(p12_file, "rb") as f:
            p12_data = f.read()

        password = None
        private_key, cert, _ = pkcs12.load_key_and_certificates(p12_data, password)

        if not private_key or not cert:
            raise ValueError("Certificado ou chave inválidos!")

        if not isinstance(private_key, (rsa.RSAPrivateKey, dh.DHPrivateKey)):
            raise ValueError("A chave privada não é do tipo esperado!")

        public_key = cert.public_key()

        issuer = cert.issuer
        issuer_attrs = {attr.oid._name: attr.value for attr in issuer}
        ca_name = issuer_attrs.get("commonName", "Unknown CA")

        subject_attrs = {attr.oid._name: attr.value for attr in cert.subject}
        user_id = subject_attrs.get("pseudonym", "UNKNOWN")

        not_valid_before = cert.not_valid_before_utc
        not_valid_after = cert.not_valid_after_utc

        return (
            cert,
            user_id,
            ca_name,
            private_key,
            public_key,
            not_valid_before,
            not_valid_after,
        )

    except Exception as e:
        print(f"\n[ERRO] Falha ao carregar credenciais: {e}")
        sys.exit(1)


def mkpair(x, y):
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y


def unpair(xy):
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y


def validate_certificate(cert, ca_cert_path="../.p12/VAULT_CA.crt"):
    try:
        now = datetime.now(tz=timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            raise x509.verification.VerificationError(
                "Certificado não válido neste momento"
            )
        with open(ca_cert_path, "rb") as f:
            ca_data = f.read()
        ca_cert = x509.load_pem_x509_certificate(ca_data)

        ca_public_key = ca_cert.public_key()

        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

        print("[OK] Certificado válido!")
        return True

    except Exception as e:
        print(f"[ERRO] Validação falhou: {e}")
        return False


def validate_certificate_user_id(
    cert, expected_user_id, ca_cert_path="../.p12/VAULT_CA.crt"
):
    try:
        now = datetime.now(tz=timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            raise x509.verification.VerificationError(
                "Certificado não válido neste momento"
            )

        try:
            pseudonym = cert.subject.get_attributes_for_oid(x509.oid.NameOID.PSEUDONYM)[
                0
            ].value
        except IndexError:
            raise ValueError("O certificado não contém o campo PSEUDONYM.")

        if pseudonym != expected_user_id:
            raise ValueError(
                f"O certificado pertence a '{pseudonym}', não a '{expected_user_id}'."
            )

        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True

    except Exception as e:
        print(f"[ERRO] Validação do certificado falhou: {e}")
        return False


def guardar_certificado(cert, user_id, pasta="../VAULT_STORAGE/metadata/certs"):
    os.makedirs(pasta, exist_ok=True)
    caminho_cert = os.path.join(pasta, f"{user_id}.crt")

    if os.path.exists(caminho_cert):
        print(f"[INFO] Certificado '{user_id}.crt' já existe. A ignorar.")
        return

    with open(caminho_cert, "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

    print(f"[OK] Certificado de '{user_id}' guardado em '{caminho_cert}'")


def carregar_certificado(user_id, pasta="../VAULT_STORAGE/metadata/certs"):
    caminho_cert = os.path.join(pasta, f"{user_id}.crt")

    if not os.path.exists(caminho_cert):
        print(f"[ERRO] Certificado de '{user_id}' não encontrado em '{pasta}/'.")
        return None

    with open(caminho_cert, "rb") as f:
        cert_pem = f.read()

    try:
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        return cert
    except Exception as e:
        print(f"[ERRO] Falha ao carregar certificado de '{user_id}': {e}")
        return None


def generate_group_id(caminho="../VAULT_STORAGE/groups"):

    while True:
        part1 = "".join(random.choice(string.ascii_lowercase) for _ in range(3))
        part2 = "".join(random.choice(string.digits) for _ in range(2))
        grupo_id = "g_" + part1 + part2
        if not os.path.exists(os.path.join(caminho, grupo_id)):
            return grupo_id


def encrypt_message(shared_key, plaintext, info=b"dh session"):
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_key)

    nonce = os.urandom(12)
    aesgcm = AESGCM(derived_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return mkpair(nonce, ciphertext)

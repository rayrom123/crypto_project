import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import base64, json
from dilithium_py.ml_dsa import ML_DSA_44

# ECDSA

def generate_ecdsa_key():
    private_key = ec.generate_private_key(ec.SECP384R1())
    return private_key

def save_ecdsa_private_key(private_key, path, password=None):
    enc_algo = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    with open(path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo
        ))

def load_ecdsa_private_key(path, password=None):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password.encode() if password else None)

def generate_ecdsa_csr(private_key, username, email, full_name, role):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, role),
        x509.NameAttribute(NameOID.GIVEN_NAME, full_name),
    ])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)

# ML-DSA (Dilithium-like, hậu lượng tử)
def generate_mldsa_keypair():
    pub, priv = ML_DSA_44.keygen()
    return pub, priv

def sign_mldsa(priv, message: bytes):
    return ML_DSA_44.sign(priv, message)

def verify_mldsa(pub, message: bytes, signature: bytes):
    return ML_DSA_44.verify(pub, message, signature)

def generate_mldsa_csr(pub, username, email, full_name, role):
    csr = {
        'username': username,
        'email': email,
        'full_name': full_name,
        'role': role,
        'public_key': base64.b64encode(pub).decode()
    }
    return json.dumps(csr) 
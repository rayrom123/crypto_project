from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime

# Sinh EC private key
private_key = ec.generate_private_key(ec.SECP384R1())

# Tạo subject và issuer (self-signed)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"VN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Hanoi"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Hanoi"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CryptoShop"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    critical=False,
).sign(private_key, hashes.SHA256())

# Lưu private key
with open("server_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Lưu certificate
with open("server_cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM)) 
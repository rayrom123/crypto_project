from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import base64
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "cryptoshop")
SERVER_CERT = os.getenv("SERVER_CERT", "server_cert.pem")
SERVER_KEY = os.getenv("SERVER_KEY", "server_key.pem")

app = FastAPI()

# Kết nối MongoDB
mongo_client = AsyncIOMotorClient(MONGO_URL)
db = mongo_client[DB_NAME]

# Model đăng ký user
class RegisterModel(BaseModel):
    username: str = Field(...)
    password: str = Field(...)
    role: str = Field(..., description="admin|buyer|seller")
    algo: str = Field(..., description="ecdsa|ml-dsa")

# Model nhận CSR
class CSRModel(BaseModel):
    username: str
    csr_pem: str  # CSR ở dạng PEM (base64)

@app.post("/register")
async def register(data: RegisterModel):
    # Kiểm tra user tồn tại
    if await db.users.find_one({"username": data.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    # Lưu user, chưa có public key/cert
    user = {
        "username": data.username,
        "password": data.password,  # TODO: hash password
        "role": data.role,
        "algo": data.algo,
        "public_key": None,
        "certificate": None
    }
    await db.users.insert_one(user)
    return {"msg": "Registered. Please use local app to generate key and CSR."}

@app.post("/csr")
async def submit_csr(data: CSRModel):
    user = await db.users.find_one({"username": data.username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Parse CSR
    try:
        csr = x509.load_pem_x509_csr(data.csr_pem.encode())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid CSR: {e}")
    # Ký certificate
    with open(SERVER_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(SERVER_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    subject = csr.subject
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        x509.datetime.datetime.utcnow()
    ).not_valid_after(
        x509.datetime.datetime.utcnow() + x509.datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(ca_key, hashes.SHA256())
    # Lưu public key và certificate vào DB
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    pubkey_pem = csr.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    await db.users.update_one(
        {"username": data.username},
        {"$set": {"public_key": pubkey_pem, "certificate": cert_pem}}
    )
    return JSONResponse(content={"certificate": cert_pem}) 
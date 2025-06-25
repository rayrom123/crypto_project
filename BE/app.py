import os
import json
import base64
import datetime
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from jose import jwt
from dotenv import load_dotenv
from bson import json_util
from bson.objectid import ObjectId
import hashlib

# Load env
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
MONGO_URL = os.getenv('MONGO_URL', 'mongodb://localhost:27017')
DB_NAME = os.getenv('DB_NAME', 'cryptoshop')
SERVER_CERT = os.getenv('SERVER_CERT', 'server_cert.pem')
SERVER_KEY = os.getenv('SERVER_KEY', 'server_key.pem')
JWT_SECRET = os.getenv('JWT_SECRET', 'supersecretjwt')

app = Flask(__name__)
app.config["MONGO_URI"] = MONGO_URL + "/" + DB_NAME
mongo = PyMongo(app)

def get_user(username):
    return mongo.db.users.find_one({"username": username})

def create_jwt(username, role):
    payload = {
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if get_user(data['username']):
        return jsonify({"error": "Username exists"}), 400
    hashed = generate_password_hash(data['password'])
    user = {
        "username": data['username'],
        "password": hashed,
        "email": data['email'],
        "full_name": data['full_name'],
        "role": data['role'],
        "algo": data['algo'],
        "public_key": None,
        "certificate": None
    }
    mongo.db.users.insert_one(user)
    return jsonify({"msg": "Registered. Please use local app to generate key and CSR."})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = get_user(data['username'])
    if not user or not check_password_hash(user['password'], data['password']):
        return jsonify({"error": "Invalid credentials"}), 401
    token = create_jwt(user['username'], user['role'])
    return jsonify({"token": token})

@app.route('/csr', methods=['POST'])
def submit_csr():
    data = request.json
    user = get_user(data['username'])
    if not user:
        return jsonify({"error": "User not found"}), 404
    try:
        if data['csr_pem'].strip().startswith("-----BEGIN"):  # ECDSA
            csr = x509.load_pem_x509_csr(data['csr_pem'].encode())
            subject = csr.subject
            pubkey = csr.public_key()
        else:  # ML-DSA (Dilithium-like)
            csr_json = json.loads(data['csr_pem'])
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, csr_json['username']),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, csr_json['email']),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, csr_json['role']),
                x509.NameAttribute(NameOID.GIVEN_NAME, csr_json['full_name']),
            ])
            pubkey_bytes = base64.b64decode(csr_json['public_key'])
            pubkey = None  # ML-DSA public key lưu dưới dạng base64
        with open(SERVER_KEY, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(SERVER_CERT, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        )
        if pubkey:
            cert_builder = cert_builder.public_key(pubkey)
        cert = cert_builder.sign(ca_key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        if pubkey:
            pubkey_pem = pubkey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        else:
            pubkey_pem = csr_json['public_key']  # base64 ML-DSA public key
        mongo.db.users.update_one(
            {"username": data['username']},
            {"$set": {"public_key": pubkey_pem, "certificate": cert_pem}}
        )
        return jsonify({"certificate": cert_pem})
    except Exception as e:
        return jsonify({"error": f"Invalid CSR: {e}"}), 400

# Product APIs
@app.route('/products', methods=['GET'])
def list_products():
    products = list(mongo.db.products.find({}, {'_id': 0}))
    return jsonify(products)

@app.route('/products', methods=['POST'])
def add_product():
    data = request.json
    # Yêu cầu JWT, role seller/admin
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return jsonify({"error": "Unauthorized"}), 401
    if payload['role'] not in ['seller', 'admin']:
        return jsonify({"error": "Permission denied"}), 403
    product = {
        "name": data['name'],
        "price": data['price'],
        "description": data.get('description', ''),
        "seller": payload['username']
    }
    mongo.db.products.insert_one(product)
    return jsonify({"msg": "Product added"})

# Order APIs
@app.route('/orders', methods=['POST'])
def create_order():
    data = request.json
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return jsonify({"error": "Unauthorized"}), 401
    if payload['role'] != 'buyer':
        return jsonify({"error": "Permission denied"}), 403
    # Tạo đơn hàng
    order = {
        "buyer": payload['username'],
        "seller": data['seller'],
        "products": data['products'],
        "created_at": datetime.datetime.now().isoformat(),
        "server_signature": None,
        "buyer_signature": None,
        "seller_signature": None,
        "status": "created",
        "sign_dates": {}
    }
    # Server ký số đơn hàng (Hybrid: ECDSA + ML-DSA)
    order_data = json.dumps({k: v for k, v in order.items() if k not in ['server_signature', 'buyer_signature', 'seller_signature', 'sign_dates', 'status']}, default=str).encode()
    
    # ECDSA signature
    with open(SERVER_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    ecdsa_signature = ca_key.sign(order_data, ec.ECDSA(hashes.SHA256()))
    
    # Mock ML-DSA signature (vì server không có LocalApp)
    h = hashlib.sha256()
    h.update(order_data + b"server_mldsa_key")
    mldsa_signature = h.digest()
    
    # Lưu cả hai chữ ký
    order['server_signature'] = {
        'ecdsa': base64.b64encode(ecdsa_signature).decode(),
        'mldsa': base64.b64encode(mldsa_signature).decode()
    }
    order['sign_dates']['server'] = datetime.datetime.now().isoformat()
    order['status'] = 'server_signed'
    mongo.db.orders.insert_one(order)
    return jsonify({"msg": "Order created, server signed (hybrid)", "order": order})

@app.route('/orders/<order_id>/sign', methods=['POST'])
def sign_order(order_id):
    data = request.json
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        order = mongo.db.orders.find_one({"_id": ObjectId(order_id)})
    except Exception:
        return jsonify({"error": "Invalid order ID format"}), 400
    if not order:
        return jsonify({"error": "Order not found"}), 404
    user = get_user(payload['username'])
    if payload['role'] == 'buyer' and not order.get('buyer_signature'):
        order_data = json.dumps({k: v for k, v in order.items() if k not in ['server_signature', 'buyer_signature', 'seller_signature', 'sign_dates', 'status', '_id']}, default=str).encode()
        # Nhận cả hai chữ ký từ local app (hybrid sign)
        ecdsa_sig = data.get('ecdsa')
        mldsa_sig = data.get('mldsa')
        if not ecdsa_sig or not mldsa_sig:
            return jsonify({"error": "Missing ECDSA or ML-DSA signature"}), 400
        # Lưu cả hai chữ ký
        order['buyer_signature'] = {
            'ecdsa': ecdsa_sig,
            'mldsa': mldsa_sig
        }
        order['sign_dates']['buyer'] = datetime.datetime.now().isoformat()
        order['status'] = 'buyer_signed'
        mongo.db.orders.update_one({"_id": ObjectId(order_id)}, {"$set": order})
        return jsonify({"msg": "Order signed by buyer (hybrid)"})
    elif payload['role'] == 'seller' and not order.get('seller_signature'):
        order_data = json.dumps({k: v for k, v in order.items() if k not in ['server_signature', 'buyer_signature', 'seller_signature', 'sign_dates', 'status', '_id']}, default=str).encode()
        # Nhận cả hai chữ ký từ local app (hybrid sign)
        ecdsa_sig = data.get('ecdsa')
        mldsa_sig = data.get('mldsa')
        if not ecdsa_sig or not mldsa_sig:
            return jsonify({"error": "Missing ECDSA or ML-DSA signature"}), 400
        # Lưu cả hai chữ ký
        order['seller_signature'] = {
            'ecdsa': ecdsa_sig,
            'mldsa': mldsa_sig
        }
        order['sign_dates']['seller'] = datetime.datetime.now().isoformat()
        order['status'] = 'completed'
        mongo.db.orders.update_one({"_id": ObjectId(order_id)}, {"$set": order})
        return jsonify({"msg": "Order signed by seller (hybrid)"})
    else:
        return jsonify({"error": "Permission denied or already signed"}), 403

@app.route('/orders/<order_id>', methods=['GET'])
def get_order(order_id):
    try:
        order = mongo.db.orders.find_one({"_id": ObjectId(order_id)})
    except Exception:
        return jsonify({"error": "Invalid order ID format"}), 400
    if not order:
        return jsonify({"error": "Order not found"}), 404
    order_json = json.loads(json_util.dumps(order))
    return jsonify(order_json)

@app.route('/orders', methods=['GET'])
def list_orders():
    orders_cursor = mongo.db.orders.find({})
    orders_list = json.loads(json_util.dumps(orders_cursor))
    return jsonify(orders_list)

if __name__ == '__main__':
    app.run(ssl_context=(SERVER_CERT, SERVER_KEY), port=8443, debug=True) 
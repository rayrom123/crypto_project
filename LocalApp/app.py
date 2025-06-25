from flask import Flask, request, jsonify
import os
from dotenv import load_dotenv
import base64
from crypto_local import (
    generate_ecdsa_key, save_ecdsa_private_key, generate_ecdsa_csr, load_ecdsa_private_key,
    generate_mldsa_keypair, sign_mldsa, generate_mldsa_csr
)
import logging
import traceback

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
KEYS_DIR = os.getenv('KEYS_DIR', os.path.join(os.path.dirname(__file__), 'keys'))
PORT = int(os.getenv('PORT', 5005))

app = Flask(__name__)
os.makedirs(KEYS_DIR, exist_ok=True)

# Cấu hình logging để ghi lỗi vào file
logging.basicConfig(filename='local_app_error.log', level=logging.ERROR,
                    format='%(asctime)s %(levelname)s: %(message)s')

@app.route('/gen_key_csr', methods=['POST'])
def gen_key_csr():
    try:
        data = request.json
        username = data['username']
        email = data['email']
        full_name = data['full_name']
        role = data['role']
        algo = data['algo']
        user_dir = os.path.join(KEYS_DIR, username)
        os.makedirs(user_dir, exist_ok=True)
        # Luôn tạo ECDSA key
        private_key = generate_ecdsa_key()
        save_ecdsa_private_key(private_key, os.path.join(user_dir, 'ecdsa_private.pem'))
        csr_pem = generate_ecdsa_csr(private_key, username, email, full_name, role)
        # Luôn tạo ML-DSA key
        pk, sk = generate_mldsa_keypair()
        with open(os.path.join(user_dir, 'dilithium_pk.bin'), 'wb') as f:
            f.write(pk)
        with open(os.path.join(user_dir, 'dilithium_sk.bin'), 'wb') as f:
            f.write(sk)
        # Trả về CSR của thuật toán được chọn
        if algo == 'ecdsa':
            return jsonify({'csr_pem': csr_pem.decode()})
        elif algo == 'ml-dsa':
            # Đọc lại pk để tạo CSR
            with open(os.path.join(user_dir, 'dilithium_pk.bin'), 'rb') as f:
                pk = f.read()
            csr_json = generate_mldsa_csr(pk, username, email, full_name, role)
            return jsonify({'csr_pem': csr_json})
        else:
            return jsonify({'error': 'Unknown algo'}), 400
    except Exception as e:
        app.logger.error(f"Lỗi không mong muốn trong gen_key_csr: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Lỗi nghiêm trọng xảy ra ở LocalApp. Vui lòng kiểm tra file local_app_error.log.'}), 500

@app.route('/save_cert', methods=['POST'])
def save_cert():
    data = request.json
    username = data['username']
    cert = data['certificate']
    user_dir = os.path.join(KEYS_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    with open(os.path.join(user_dir, 'certificate.pem'), 'w') as f:
        f.write(cert)
    return jsonify({'msg': 'Certificate saved'})

@app.route('/hybrid_sign', methods=['POST'])
def hybrid_sign():
    data = request.json
    username = data['username']
    message = data['message'].encode()
    user_dir = os.path.join(KEYS_DIR, username)
    # ECDSA
    priv_path = os.path.join(user_dir, 'ecdsa_private.pem')
    private_key = load_ecdsa_private_key(priv_path)
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    sig_ecdsa = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    sig_ecdsa_b64 = base64.b64encode(sig_ecdsa).decode()
    # ML-DSA
    sig_mldsa_b64 = None
    try:
        with open(os.path.join(user_dir, 'dilithium_sk.bin'), 'rb') as f:
            sk = f.read()
        sig_mldsa = sign_mldsa(sk, message)
        sig_mldsa_b64 = base64.b64encode(sig_mldsa).decode()
    except Exception as e:
        sig_mldsa_b64 = None
    return jsonify({'ecdsa': sig_ecdsa_b64, 'mldsa': sig_mldsa_b64})

if __name__ == '__main__':
    cert_path = os.path.join(os.path.dirname(__file__), 'certs', 'local_cert.pem')
    key_path = os.path.join(os.path.dirname(__file__), 'certs', 'local_key.pem')
    context = (cert_path, key_path)
    app.run(port=PORT, debug=True, ssl_context=context) 
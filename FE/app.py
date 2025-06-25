from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

BACKEND_URL = os.getenv('BACKEND_URL', 'https://localhost:8443')
LOCALAPP_URL = os.getenv('LOCALAPP_URL', 'https://localhost:5005')
SECRET_KEY = os.getenv('SECRET_KEY', 'supersecretkey')
LOCAL_CERT_PATH = os.path.join(os.path.dirname(__file__), '..', 'LocalApp', 'certs', 'local_cert.pem')
BACKEND_CERT_PATH = os.path.join(os.path.dirname(__file__), '..', 'BE', 'server_cert.pem')

app = Flask(__name__)
app.secret_key = SECRET_KEY

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        full_name = request.form['full_name']
        role = request.form['role']
        # Không lấy algo từ form nữa, luôn dùng hybrid
        algo = 'hybrid'
        # Gọi backend để đăng ký
        r = requests.post(f'{BACKEND_URL}/register', json={
            'username': username,
            'password': password,
            'email': email,
            'full_name': full_name,
            'role': role,
            'algo': algo
        }, verify=BACKEND_CERT_PATH)
        if r.status_code == 200:
            # Gọi local app để sinh cả hai loại key và tạo CSR (CSR chuẩn chỉ hỗ trợ ECDSA)
            r2 = requests.post(f'{LOCALAPP_URL}/gen_key_csr', json={
                'username': username,
                'email': email,
                'full_name': full_name,
                'role': role,
                'algo': 'ecdsa'
            }, verify=False)
            if r2.status_code == 200:
                csr_pem = r2.json()['csr_pem']
                # Gửi CSR lên backend để lấy cert
                r3 = requests.post(f'{BACKEND_URL}/csr', json={
                    'username': username,
                    'csr_pem': csr_pem
                }, verify=BACKEND_CERT_PATH)
                if r3.status_code == 200:
                    cert = r3.json()['certificate']
                    # Lưu cert về local (gọi local app)
                    requests.post(f'{LOCALAPP_URL}/save_cert', json={
                        'username': username,
                        'certificate': cert
                    }, verify=False)
                    flash('Đăng ký thành công!')
                    return redirect(url_for('login'))
                else:
                    flash(f"Lỗi lấy certificate từ backend! {r3.text}")
            else:
                flash(f"Lỗi sinh key hoặc CSR ở local! {r2.text}")
        else:
            flash(f"Lỗi đăng ký backend! {r.text}")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        r = requests.post(f'{BACKEND_URL}/login', json={
            'username': username,
            'password': password
        }, verify=BACKEND_CERT_PATH)
        if r.status_code == 200:
            token = r.json()['token']
            # Lấy role từ JWT payload (giản lược, thực tế nên decode)
            import jwt
            payload = jwt.decode(token, options={"verify_signature": False})
            session['username'] = username
            session['role'] = payload['role']
            session['token'] = token
            return redirect(url_for('dashboard'))
        else:
            flash('Sai tài khoản hoặc mật khẩu!')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'], role=session['role'])

@app.route('/products', methods=['GET', 'POST'])
def products():
    token = session.get('token')
    role = session.get('role')
    if request.method == 'POST' and role in ['seller', 'admin']:
        name = request.form['name']
        price = float(request.form['price'])
        desc = request.form.get('description', '')
        r = requests.post(f'{BACKEND_URL}/products',
            headers={'Authorization': f'Bearer {token}'},
            json={'name': name, 'price': price, 'description': desc},
            verify=BACKEND_CERT_PATH
        )
        if r.status_code == 200:
            flash('Thêm sản phẩm thành công!')
    r = requests.get(f'{BACKEND_URL}/products', verify=BACKEND_CERT_PATH)
    products = r.json()
    return render_template('products.html', products=products, role=role)

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if 'role' not in session or session['role'] != 'buyer':
        return redirect(url_for('products'))
    product_id = request.form['product_id']
    cart = session.get('cart', [])
    if product_id not in cart:
        cart.append(product_id)
    session['cart'] = cart
    flash('Đã thêm vào giỏ hàng!')
    return redirect(url_for('products'))

@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    if 'role' not in session or session['role'] != 'buyer':
        return redirect(url_for('orders'))
    product_id = request.form['product_id']
    cart = session.get('cart', [])
    if product_id in cart:
        cart.remove(product_id)
    session['cart'] = cart
    return redirect(url_for('orders'))

@app.route('/orders', methods=['GET', 'POST'])
def orders():
    token = session.get('token')
    username = session.get('username')
    role = session.get('role')
    cart = session.get('cart', [])
    r2 = requests.get(f'{BACKEND_URL}/products', verify=BACKEND_CERT_PATH)
    products = r2.json()
    if request.method == 'POST' and role == 'buyer':
        # Nhóm sản phẩm trong giỏ theo seller
        seller_products = {}
        for pid in cart:
            for p in products:
                pid_match = (p.get('_id') and '$oid' in p['_id'] and p['_id']['$oid'] == pid) or (not p.get('_id') and p.get('name') == pid)
                if pid_match:
                    seller = p['seller']
                    if seller not in seller_products:
                        seller_products[seller] = []
                    # Lưu id hoặc name tùy trường hợp
                    if p.get('_id') and p['_id'].get('$oid'):
                        seller_products[seller].append(p['_id']['$oid'])
                    else:
                        seller_products[seller].append(p.get('name'))
        # Tạo đơn hàng cho từng seller
        for seller, product_ids in seller_products.items():
            r = requests.post(f'{BACKEND_URL}/orders',
                headers={'Authorization': f'Bearer {token}'},
                json={'seller': seller, 'products': product_ids},
                verify=BACKEND_CERT_PATH
            )
            if r.status_code == 200:
                flash(f'Tạo đơn hàng thành công cho seller {seller}!')
            else:
                flash(f'Lỗi tạo đơn hàng cho seller {seller}!')
        session['cart'] = []  # Xóa giỏ hàng sau khi đặt
    # Lấy danh sách đơn hàng và chỉ lọc của buyer hoặc seller hiện tại
    r = requests.get(f'{BACKEND_URL}/orders', verify=BACKEND_CERT_PATH)
    all_orders = r.json()
    if role == 'buyer':
        orders = [o for o in all_orders if o.get('buyer') == username]
    elif role == 'seller':
        orders = [o for o in all_orders if o.get('seller') == username]
    else:
        orders = all_orders
    return render_template('orders.html', orders=orders, role=role, username=username, cart=cart, products=products)

@app.route('/orders/<order_id>/sign', methods=['POST'])
def sign_order(order_id):
    token = session.get('token')
    username = session.get('username')
    role = session.get('role')
    # Lấy dữ liệu đơn hàng
    r = requests.get(f'{BACKEND_URL}/orders/{order_id}', verify=BACKEND_CERT_PATH)
    if r.status_code != 200:
        flash('Không tìm thấy đơn hàng!')
        return redirect(url_for('orders'))
    order = r.json()
    # Ký số hybrid bằng local app
    message = str(order).encode().decode('utf-8')
    r2 = requests.post(f'{LOCALAPP_URL}/hybrid_sign', json={
        'username': username,
        'message': message
    }, verify=False)
    if r2.status_code == 200:
        sigs = r2.json()
        # Gửi cả hai chữ ký lên backend
        r3 = requests.post(f'{BACKEND_URL}/orders/{order_id}/sign',
            headers={'Authorization': f'Bearer {token}'},
            json={'ecdsa': sigs['ecdsa'], 'mldsa': sigs['mldsa']},
            verify=BACKEND_CERT_PATH
        )
        if r3.status_code == 200:
            flash('Ký số thành công!')
        else:
            flash('Lỗi gửi chữ ký lên backend!')
    else:
        flash('Lỗi ký số ở local app!')
    return redirect(url_for('orders'))

if __name__ == '__main__':
    # Gợi ý chạy Flask với SSL nếu cần
    # app.run(port=5000, debug=True, ssl_context=('cert.pem', 'key.pem'))
    app.run(port=5000, debug=True) 
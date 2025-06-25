 # CryptoShop - Hệ thống bán hàng ký số đa thuật toán

## 1. Yêu cầu hệ thống
- Python 3.8+
- MongoDB Community Server
- pip (Python package manager)

## 2. Cài đặt các package cần thiết

### Backend (BE)
```bash
cd BE
pip install -r requirements.txt
```

### LocalApp
```bash
cd ../LocalApp
pip install -r requirements.txt
```

### Frontend (FE)
```bash
cd ../FE
pip install -r requirements.txt
```

## 3. Tạo file cấu hình `.env`

### BE/.env
```
MONGO_URL=mongodb://localhost:27017
DB_NAME=cryptoshop
SERVER_CERT=server_cert.pem
SERVER_KEY=server_key.pem
JWT_SECRET=supersecretjwt
```

### FE/.env
```
BACKEND_URL=https://localhost:8443
LOCALAPP_URL=http://localhost:5005
SECRET_KEY=supersecretkey
```

### LocalApp/.env
```
KEYS_DIR=./keys
PORT=5005
```

## 4. Khởi tạo certificate cho server (BE)

Chạy script sau trong thư mục `BE` để sinh cặp khóa và certificate EC cho server:
```bash
cd BE
python gen_server_cert.py
```
Sau khi chạy sẽ có 2 file: `server_cert.pem` và `server_key.pem` trong thư mục `BE`.

## 5. Khởi động MongoDB
- Đảm bảo MongoDB đã được cài đặt và đang chạy (thường là `mongod` hoặc qua MongoDB Compass).

## 6. Khởi động các service

### Cách 1: Chạy từng service ở từng terminal
```bash
# Terminal 1
cd LocalApp
python app.py

# Terminal 2
cd BE
python app.py

# Terminal 3
cd FE
python app.py
```

### Cách 2: Chạy đồng thời bằng script Python
Tạo file `run_all.py` ở thư mục gốc với nội dung:
```python
import subprocess
import os
import time

def run_service(path, cmd):
    return subprocess.Popen(cmd, cwd=path, shell=True)

processes = []
processes.append(run_service('LocalApp', 'python app.py'))
time.sleep(2)
processes.append(run_service('BE', 'python app.py'))
processes.append(run_service('FE', 'python app.py'))
print("Tất cả service đã được khởi động!")
print("Nhấn Ctrl+C để dừng tất cả.")
try:
    for p in processes:
        p.wait()
except KeyboardInterrupt:
    print("Đang dừng các service...")
    for p in processes:
        p.terminate()
```
Chạy:
```bash
python run_all.py
```

## 7. Truy cập hệ thống
- FE chạy ở: http://localhost:5000
- Đăng ký, đăng nhập, thao tác mua/bán, ký số, tra cứu đơn hàng qua giao diện web.

## 8. Lưu ý bảo mật
- Private key của user chỉ lưu ở LocalApp (máy local)
- Certificate của user chứa đầy đủ thông tin, do server ký
- Giao tiếp giữa các thành phần qua HTTPS (có thể cần chấp nhận self-signed cert khi test)

## 9. Troubleshooting
- Nếu gặp lỗi, kiểm tra log của từng service (BE, FE, LocalApp)
- Đảm bảo các port không bị trùng, các file `.env` đúng cấu hình
- Đảm bảo MongoDB đang chạy

---
**Mọi thắc mắc hoặc lỗi phát sinh, hãy liên hệ để được hỗ trợ!**

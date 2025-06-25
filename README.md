 # CryptoShop - Hệ thống bán hàng ký số đa thuật toán

## 1. Yêu cầu hệ thống
- Python 3.8+
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

## 3. Khởi tạo certificate cho server (BE)

Chạy script sau trong thư mục `BE` để sinh cặp khóa và certificate EC cho server:
```bash
cd BE
python gen_server_cert.py
```
Sau khi chạy sẽ có 2 file: `server_cert.pem` và `server_key.pem` trong thư mục `BE`.


## 4. Khởi động các service

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
```
Chạy:
```bash
python run_all.py
```

## 5. Truy cập hệ thống
- FE chạy ở: http://localhost:5000
- Đăng ký, đăng nhập, thao tác mua/bán, ký số, tra cứu đơn hàng qua giao diện web.

## 6. Lưu ý bảo mật
- Private key của user chỉ lưu ở LocalApp (máy local)
- Certificate của user chứa đầy đủ thông tin, do server ký
- Giao tiếp giữa các thành phần qua HTTPS (có thể cần chấp nhận self-signed cert khi test)

## 7. Troubleshooting
- Nếu gặp lỗi, kiểm tra log của từng service (BE, FE, LocalApp)

---
**Mọi thắc mắc hoặc lỗi phát sinh, hãy liên hệ để được hỗ trợ!**

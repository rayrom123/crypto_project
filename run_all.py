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
"""
Tam entegrasyon testi: server.py + client.py birlikte calisir.
Thread'de server baslatilir, client gercek CLI akisiyla calisir.
"""
import sys, os, socket, threading, time, tempfile, subprocess
os.environ['PYTHONIOENCODING'] = 'utf-8'

ROOT = r'c:\Users\baris\OneDrive\Desktop\bilgisayar aglari'
sys.path.insert(0, ROOT)

from netprobe.protocol import verify_file_integrity

HOST = '127.0.0.1'
PORT = 19880

# 30 KB test dosyasi
test_data = bytes([i % 200 for i in range(30 * 1024)])
orig_fd, orig_path = tempfile.mkstemp(suffix='.bin', dir=ROOT)
os.write(orig_fd, test_data)
os.close(orig_fd)

print('=== Tam Entegrasyon Testi (server.py + client.py, GBN) ===')
print(f'Test dosyasi: {orig_path} ({len(test_data):,} byte)')
print()

# 1. Hata testi: var olmayan dosya
print('--- Test 1: Var olmayan dosya hatasi ---')
res = subprocess.run(
    [sys.executable, 'client.py', '--file', 'yok_dosya.bin', '--port', str(PORT)],
    capture_output=True, text=True, cwd=ROOT, timeout=10
)
assert res.returncode != 0, 'Hata kodu beklendi!'
print(f'  Cikis kodu: {res.returncode} (beklenen: != 0) - OK')
assert 'bulunamadi' in res.stdout.lower() or 'hata' in res.stdout.lower()
print(f'  Hata mesaji mevcut - OK')
print()

# 2. Gercek transfer testi
print('--- Test 2: Gercek transfer (GBN, window=4) ---')

server_ready = threading.Event()
server_done  = threading.Event()
server_output = []

def run_server_proc():
    import socket as _sock, time as _time
    # Sunucuyu thread icinde manuel calistir
    sys.path.insert(0, ROOT)
    os.chdir(ROOT)
    from netprobe.logger   import NetLogger
    from netprobe.protocol import ProtocolConfig, ProtocolMode
    from netprobe.receiver import Receiver
    from netprobe.stats    import StatsCalculator

    s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
    s.bind((HOST, PORT))
    server_ready.set()

    logger = NetLogger(log_level='WARN')
    cfg    = ProtocolConfig(mode=ProtocolMode.GBN, window_size=4)
    rcvr   = Receiver(s, logger, cfg)

    out_path = orig_path + '_srv_recv.bin'
    result   = rcvr.receive_file(out_path)
    server_output.append((result, out_path))
    s.close()
    logger.close()
    server_done.set()

t = threading.Thread(target=run_server_proc, daemon=True)
t.start()
server_ready.wait(timeout=5)
time.sleep(0.1)

# Client'i subprocess ile calistir (gercek CLI deneyimi)
res = subprocess.run(
    [sys.executable, 'client.py',
     '--file',   orig_path,
     '--port',   str(PORT),
     '--mode',   'GBN',
     '--window', '4',
     '--chunk',  '1024',
     '--log-level', 'WARN'],
    capture_output=True, text=True, cwd=ROOT, timeout=30
)

server_done.wait(timeout=15)

print(f'  Client cikis kodu: {res.returncode}')
if res.returncode != 0:
    print('  STDOUT:', res.stdout[-300:])
    print('  STDERR:', res.stderr[-300:])
    assert False, 'Client basarisiz!'

# MD5 dogrulama
result, recv_path = server_output[0]
ok = verify_file_integrity(orig_path, recv_path)
print(f'  Alinan paket    : {result["received_packets"]}')
print(f'  Dosya boyutu    : {result["file_size_bytes"]:,} byte')
print(f'  MD5 eslesmesi   : {ok}')
assert ok, 'Dosya bütünlügü hatasi!'

# JSON rapor kontrolü
import glob
reports = glob.glob(os.path.join(ROOT, 'reports', '*.json'))
assert len(reports) > 0, 'JSON rapor bulunamadi!'
latest  = max(reports, key=os.path.getmtime)
import json
with open(latest, encoding='utf-8') as f:
    rpt = json.load(f)
assert 'meta'    in rpt, 'meta eksik'
assert 'metrics' in rpt, 'metrics eksik'
assert rpt['meta']['mode'] == 'GBN'
print(f'  JSON rapor      : {os.path.basename(latest)} - OK')
print(f'  Throughput      : {rpt["metrics"]["throughput_bps"]/1000:.2f} KB/s')

# Temizlik
os.unlink(orig_path)
os.unlink(recv_path)

# 3. Kayıplı CLI transfer testi
print('--- Test 3: Kayıplı transfer (GBN, window=4, loss=0.2, delay=10) ---')

server_ready2 = threading.Event()
server_done2  = threading.Event()
server_output2 = []
PORT2 = 19881

# Yeni test dosyası oluşturalım
orig_fd2, orig_path2 = tempfile.mkstemp(suffix='.bin', dir=ROOT)
test_data2 = bytes([i % 251 for i in range(25 * 1024)])
os.write(orig_fd2, test_data2)
os.close(orig_fd2)

def run_server_proc2():
    import socket as _sock, time as _time
    sys.path.insert(0, ROOT)
    os.chdir(ROOT)
    from netprobe.logger   import NetLogger
    from netprobe.protocol import ProtocolConfig, ProtocolMode
    from netprobe.receiver import Receiver
    from simulator.network_emulator import NetworkEmulator

    s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
    s.bind((HOST, PORT2))
    
    # Sunucu tarafında da kayıp
    emulator = NetworkEmulator(loss_prob=0.2, delay_ms=10)
    s_wrapped = emulator.wrap_socket(s)
    
    server_ready2.set()

    logger = NetLogger(log_level='WARN')
    emulator.logger = logger
    cfg    = ProtocolConfig(mode=ProtocolMode.GBN, window_size=4)

    out_path = orig_path2 + '_srv_recv.bin'
    result   = Receiver(s_wrapped, logger, cfg).receive_file(out_path)
    server_output2.append((result, out_path))
    s.close()
    logger.close()
    server_done2.set()

t2 = threading.Thread(target=run_server_proc2, daemon=True)
t2.start()
server_ready2.wait(timeout=5)
time.sleep(0.1)

# Client'ı subprocess ile çalıştır (--loss 0.2 ve --delay 10 ile)
res2 = subprocess.run(
    [sys.executable, 'client.py',
     '--file',   orig_path2,
     '--port',   str(PORT2),
     '--mode',   'GBN',
     '--window', '4',
     '--chunk',  '1024',
     '--loss',   '0.2',
     '--delay',  '10',
     '--log-level', 'WARN'],
    capture_output=True, text=True, cwd=ROOT, timeout=45
)

server_done2.wait(timeout=20)

print(f'  Client çıkış kodu: {res2.returncode}')
if res2.returncode != 0:
    print('  STDOUT:', res2.stdout[-300:])
    print('  STDERR:', res2.stderr[-300:])
    assert False, 'Client başarısız!'

# MD5 doğrulama
result2, recv_path2 = server_output2[0]
ok2 = verify_file_integrity(orig_path2, recv_path2)
print(f'  Alınan paket    : {result2["received_packets"]}')
print(f'  Dosya boyutu    : {result2["file_size_bytes"]:,} byte')
print(f'  MD5 eşleşmesi   : {ok2}')
assert ok2, 'Dosya bütünlüğü hatası!'

# Rapor kontrolü
reports2 = glob.glob(os.path.join(ROOT, 'reports', '*.json'))
assert len(reports2) > 0, 'JSON rapor bulunamadı!'
latest2  = max(reports2, key=os.path.getmtime)
with open(latest2, encoding='utf-8') as f:
    rpt2 = json.load(f)
assert rpt2['meta']['loss_prob'] == 0.2
assert rpt2['meta']['delay_ms'] == 10
print(f'  JSON rapor (loss): {os.path.basename(latest2)} - OK')

# Temizlik
os.unlink(orig_path2)
os.unlink(recv_path2)

print()
print('=== TUM ENTEGRASYON TESTLERI BASARILI ===')


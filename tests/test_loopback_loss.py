import sys, os, socket, threading, time, tempfile
os.environ['PYTHONIOENCODING'] = 'utf-8'
sys.path.insert(0, r'c:\Users\baris\OneDrive\Desktop\bilgisayar aglari')

from netprobe.logger   import NetLogger
from netprobe.protocol import ProtocolConfig, ProtocolMode, verify_file_integrity
from netprobe.sender   import Sender
from netprobe.receiver import Receiver
from netprobe.stats    import StatsCalculator
from simulator.network_emulator import NetworkEmulator

print('=== Loopback Entegrasyon Testi (GBN, window=4, loss=0.2) ===')

HOST = '127.0.0.1'
PORT = 19879

# 20 KB test dosyası
test_data = bytes([i % 251 for i in range(20 * 1024)])
orig_fd, orig_path = tempfile.mkstemp(suffix='.bin')
os.write(orig_fd, test_data)
os.close(orig_fd)
recv_path = orig_path + '_recv.bin'

server_ready = threading.Event()
server_done  = threading.Event()
server_result = {}

def run_server():
    s_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_sock.bind((HOST, PORT))
    
    # Sunucu tarafında da %20 kayıp simüle edelim (giden ACK'ler için)
    emulator = NetworkEmulator(loss_prob=0.2)
    s_sock_wrapped = emulator.wrap_socket(s_sock)
    
    server_ready.set()
    s_logger = NetLogger(log_level='INFO')
    emulator.logger = s_logger
    
    s_cfg    = ProtocolConfig(mode=ProtocolMode.GBN, window_size=4)
    rcvr     = Receiver(s_sock_wrapped, s_logger, s_cfg)
    result   = rcvr.receive_file(recv_path, original_path=orig_path)
    server_result.update(result)
    s_sock.close()
    s_logger.close()
    server_done.set()

t = threading.Thread(target=run_server, daemon=True)
t.start()
server_ready.wait(timeout=3)

c_sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# İstemci tarafında %20 kayıp simüle edelim (giden veriler için)
c_emulator = NetworkEmulator(loss_prob=0.2)
c_sock_wrapped = c_emulator.wrap_socket(c_sock)

c_logger = NetLogger(log_level='INFO')
c_emulator.logger = c_logger

c_cfg    = ProtocolConfig(mode=ProtocolMode.GBN, window_size=4, timeout_sec=0.5)
sender   = Sender(c_sock_wrapped, (HOST, PORT), c_logger, c_cfg)

t_start = time.monotonic()
stats   = sender.send_file(orig_path)
elapsed = time.monotonic() - t_start

server_done.wait(timeout=30)
c_sock.close()

print()
print('--- Sonuçlar (Kayıplı Transfer) ---')
print('  Gönderilen  :', stats['file_size_bytes'], 'byte')
print('  Parça sayısı:', stats['total_chunks'])
print('  Süre        :', round(elapsed, 4), 's')
print('  Kaybolan    :', stats['total_lost'])
print('  Yeniden Gönd:', c_logger.get_events()) # Event'leri sayabiliriz
print('  Sunucu aldı :', server_result.get('received_packets'), 'paket')
print('  Dosya boyutu:', server_result.get('file_size_bytes'), 'byte')

ok = verify_file_integrity(orig_path, recv_path)
print('  MD5 eşleşti :', ok)
assert ok, 'MD5 uyuşmazlığı!'

c_logger.close()
os.unlink(orig_path)
if os.path.exists(recv_path):
    os.unlink(recv_path)
print('=== GBN KAYIPLI LOOPBACK TESTİ BAŞARILI ===')

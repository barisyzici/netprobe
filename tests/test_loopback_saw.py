import sys, os, socket, threading, time, tempfile
os.environ['PYTHONIOENCODING'] = 'utf-8'
sys.path.insert(0, r'c:\Users\baris\OneDrive\Desktop\bilgisayar aglari')

from netprobe.logger   import NetLogger
from netprobe.protocol import ProtocolConfig, ProtocolMode, verify_file_integrity
from netprobe.sender   import Sender
from netprobe.receiver import Receiver
from netprobe.stats    import StatsCalculator

print('=== Loopback Entegrasyon Testi (SAW) ===')

HOST = '127.0.0.1'
PORT = 19876

# 5 KB test dosyasi
test_data = bytes([i % 256 for i in range(5120)])
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
    server_ready.set()
    s_logger = NetLogger(log_level='WARN')
    s_cfg    = ProtocolConfig(mode=ProtocolMode.SAW)
    rcvr     = Receiver(s_sock, s_logger, s_cfg)
    result   = rcvr.receive_file(recv_path, original_path=orig_path)
    server_result.update(result)
    s_sock.close()
    s_logger.close()
    server_done.set()

t = threading.Thread(target=run_server, daemon=True)
t.start()
server_ready.wait(timeout=3)

c_sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c_logger = NetLogger(log_level='WARN')
c_cfg    = ProtocolConfig(mode=ProtocolMode.SAW)
sender   = Sender(c_sock, (HOST, PORT), c_logger, c_cfg)
stats    = sender.send_file(orig_path)

server_done.wait(timeout=15)
c_sock.close()

print('  Gonderilen  :', stats['file_size_bytes'], 'byte')
print('  Parca sayisi:', stats['total_chunks'])
print('  Sure        :', round(stats['completion_time_s'], 4), 's')
print('  Kayip paket :', stats['total_lost'])
print('  Sunucu aldi :', server_result.get('received_packets'), 'paket')
print('  Dosya boyutu:', server_result.get('file_size_bytes'), 'byte')

ok = verify_file_integrity(orig_path, recv_path)
print('  MD5 eslesti :', ok)
assert ok, 'MD5 uyusmazligi!'

calc = StatsCalculator(c_logger)
calc.print_report(
    total_bytes_sent  = stats['total_bytes_sent'],
    file_size_bytes   = stats['file_size_bytes'],
    total_sent        = stats['total_chunks'],
    total_lost        = stats['total_lost'],
    completion_time_s = stats['completion_time_s'],
)

c_logger.close()
os.unlink(orig_path)
os.unlink(recv_path)
print('=== LOOPBACK TESTI BASARILI ===')

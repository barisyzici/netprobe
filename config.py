"""
config.py
=========
NetProbe — UDP Tabanlı Güvenilir Dosya Aktarım Sistemi
Bursa Teknik Üniversitesi | Bilgisayar Ağları Dersi

Tüm ayarlanabilir sabitleri tek bir yerden yönetir.
Herhangi bir parametreyi değiştirmek için yalnızca bu dosyayı düzenleyin;
başka hiçbir kaynak dosyasına dokunmanıza gerek yoktur.
"""

# ---------------------------------------------------------------------------
# Ağ / Soket Ayarları
# ---------------------------------------------------------------------------

SERVER_IP: str = "127.0.0.1"
"""Sunucunun dinleyeceği (veya istemcinin bağlanacağı) IP adresi."""

SERVER_PORT: int = 9000
"""UDP port numarası. 1024–65535 arasında olmalıdır."""

SOCKET_BUFFER_SIZE: int = 65535
"""UDP soket okuma tamponu (byte). Sistem maksimumunu aşmamalıdır."""

# ---------------------------------------------------------------------------
# Protokol Parametreleri
# ---------------------------------------------------------------------------

MODE: str = "GBN"
"""
Güvenilir aktarım protokol modu.
  'SAW' → Stop-and-Wait      (WINDOW_SIZE=1, en sade)
  'GBN' → Go-Back-N          (hatalı paketten itibaren tümünü yeniden gönder)
  'SR'  → Selective Repeat   (yalnızca eksik paketi yeniden gönder)
"""

CHUNK_SIZE: int = 1024
"""
Tek bir DATA paketinin taşıyabileceği maksimum veri boyutu (byte).
Paket başlığı (13 byte) bu değere dahil değildir.
UDP datagram sınırı nedeniyle maksimum değer ~65494 byte'tır.
"""

WINDOW_SIZE: int = 4
"""
Sliding Window boyutu (paket sayısı).
  SAW modunda bu değer 1'e zorlanır.
  GBN/SR modlarında 1–255 arası değer alabilir.
"""

TIMEOUT_SEC: float = 0.5
"""
Bir ACK için bekleme süresi (saniye).
Bu süre geçmeden ACK alınmazsa retransmission tetiklenir.
"""

MAX_RETRIES: int = 5
"""
Tek bir paket için maksimum yeniden gönderme denemesi.
Bu sınıra ulaşıldığında aktarım hata ile sonlandırılır.
"""

# ---------------------------------------------------------------------------
# Simülatör Ayarları (network_emulator.py için)
# ---------------------------------------------------------------------------

LOSS_PROB: float = 0.0
"""
Simülatörün bir paketi yapay olarak düşürme olasılığı [0.0 – 1.0].
  0.0  → Paket kaybı yok (gerçek ağ davranışı)
  0.1  → Her 10 paketten 1'i düşürülür (%10 kayıp)
  1.0  → Tüm paketler düşürülür (bağlantısızlık testi)
"""

DELAY_MS: int = 0
"""
Simülatörün her pakete ekleyeceği yapay gecikme (milisaniye).
0 değerinde gecikme eklenmez.
"""

# ---------------------------------------------------------------------------
# Günlük Kayıt (Logging) Ayarları
# ---------------------------------------------------------------------------

LOG_LEVEL: str = "INFO"
"""
Konsol ve dosya çıktısı için günlük seviyesi.
  'DEBUG' → Her paket hareketi ayrıntılı olarak gösterilir
  'INFO'  → Önemli olaylar (SEND, ACK, TIMEOUT, FIN) gösterilir
  'WARN'  → Yalnızca uyarı ve hatalar gösterilir
"""

LOG_DIR: str = "logs"
"""Çalışma zamanı log dosyalarının kaydedileceği klasör."""

LOG_FORMAT: str = "jsonl"
"""
Log dosyası formatı.
  'jsonl' → Her satır bağımsız bir JSON nesnesidir (makine tarafından okunabilir)
  'text'  → Düz metin (insan tarafından okunabilir)
"""

# ---------------------------------------------------------------------------
# Performans Raporu Ayarları
# ---------------------------------------------------------------------------

REPORT_DIR: str = "reports"
"""Aktarım sonrası performans raporlarının kaydedileceği klasör."""

# ---------------------------------------------------------------------------
# Paket Tipi Sabitleri (packet.py ile senkronize — buradan okunur)
# ---------------------------------------------------------------------------

PKT_DATA: int = 0x01
"""DATA paketi tip kodu."""

PKT_ACK: int = 0x02
"""ACK paketi tip kodu."""

PKT_FIN: int = 0x03
"""FIN (bağlantı sonlandırma) paketi tip kodu."""

PKT_FIN_ACK: int = 0x04
"""FIN-ACK (sonlandırma onayı) paketi tip kodu."""

# ---------------------------------------------------------------------------
# ACK Status Sabitleri
# ---------------------------------------------------------------------------

STATUS_OK: int = 0x00
"""Paket başarıyla alındı."""

STATUS_NAK: int = 0x01
"""Paket hatalı alındı (checksum hatası veya sıra dışı)."""

STATUS_BUFFER_FULL: int = 0xFF
"""Alıcı tamponu dolu; gönderici yavaşlamalıdır."""

# NetProbe

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/barisyzici/netprobe)

UDP tabanlı güvenilir dosya aktarım (Reliable Data Transfer - RDT) ve performans analiz sistemi. NetProbe; sequence number, ACK, timeout ve retransmission gibi mekanizmaları UDP üzerinde uygulayarak kayıplı ve gecikmeli ağ ortamlarında dahi dosya bütünlüğünü koruyarak güvenilir veri aktarımı sağlar.

Bursa Teknik Üniversitesi Bilgisayar Ağları Dersi Projesi kapsamında geliştirilmiştir.


---

## 🚀 Kurulum

Projeyi çalıştırmak için öncelikle gerekli bağımlılıkları yükleyin:

```bash
pip install -r requirements.txt
```

*Not: NetProbe harici kütüphane olarak veri görselleştirme için `matplotlib` ve testler için `pytest` kullanmaktadır.*

---

## 💻 Çalıştırma Adımları

NetProbe, iki farklı güvenilir aktarım protokolü modunu destekler: **Stop-and-Wait (SAW)** ve **Go-Back-N (GBN)**. Aktarımı başlatmak için öncelikle sunucu (alıcı) terminalini, ardından istemci (gönderici) terminalini çalıştırın.

### 1. Stop-and-Wait (SAW) Modu Örneği

**Terminal 1 (Sunucu):**
```bash
# Sunucuyu 9000 portunda, SAW modunda başlat
python server.py --port 9000 --mode SAW --output ./received/
```

**Terminal 2 (İstemci):**
```bash
# buyuk_dosya.bin dosyasını 9000 portundaki sunucuya SAW modunda gönder
python client.py --file buyuk_dosya.bin --port 9000 --mode SAW
```

---

### 2. Go-Back-N (GBN) Modu Örneği

**Terminal 1 (Sunucu):**
```bash
# Sunucuyu GBN modunda başlat (varsayılan port 9000'dir)
python server.py --mode GBN --output ./received/
```

**Terminal 2 (İstemci):**
```bash
# Dosyayı sliding window boyutu 8 ve timeout süresi 0.5 saniye olacak şekilde GBN modunda gönder
python client.py --file buyuk_dosya.bin --mode GBN --window 8 --timeout 0.5
```

---

## ⚙️ CLI Argümanları

### Sunucu Argümanları (`server.py`)

| Argüman | Kısa Yol | Tür | Varsayılan | Açıklama |
| :--- | :--- | :--- | :--- | :--- |
| `--port` | `-p` | `int` | `9000` | Dinlenecek UDP port numarası. |
| `--output` | `-o` | `str` | `./received/` | Alınan dosyaların kaydedileceği klasör yolu. |
| `--mode` | `-m` | `str` | `GBN` | Güvenilir aktarım modu: `SAW` \| `GBN` \| `SR`. |
| `--loss` | `-l` | `float`| `0.0` | Simüle edilecek paket kayıp olasılığı [0.0 - 1.0]. |
| `--delay` | `-d` | `int` | `0` | Simüle edilecek ağ gecikmesi (milisaniye). |
| `--log-level`| | `str` | `INFO` | Günlük kayıt seviyesi: `DEBUG` \| `INFO` \| `WARN`. |

### İstemci Argümanları (`client.py`)

| Argüman | Kısa Yol | Tür | Varsayılan | Açıklama |
| :--- | :--- | :--- | :--- | :--- |
| `--file` | `-f` | `str` | *(Zorunlu)* | Gönderilecek dosyanın tam veya bağıl yolu. |
| `--server` | `-s` | `str` | `127.0.0.1` | Hedef sunucunun IP adresi. |
| `--port` | `-p` | `int` | `9000` | Hedef UDP port numarası. |
| `--mode` | `-m` | `str` | `GBN` | Güvenilir aktarım modu: `SAW` \| `GBN` \| `SR`. |
| `--timeout` | `-t` | `float`| `0.5` | ACK beklemek için zaman aşımı süresi (saniye). |
| `--chunk` | `-c` | `int` | `1024` | Paket başına düşen veri yükü boyutu (byte). |
| `--window` | `-w` | `int` | `4` | Sliding window (kayan pencere) boyutu (GBN için). |
| `--loss` | `-l` | `float`| `0.0` | Simüle edilecek giden paket kayıp olasılığı [0.0 - 1.0]. |
| `--delay` | `-d` | `int` | `0` | Simüle edilecek ek ağ gecikmesi (milisaniye). |
| `--log-level`| | `str` | `INFO` | Günlük kayıt seviyesi: `DEBUG` \| `INFO` \| `WARN`. |

### Analizci Argümanları (`analyze.py`)

| Argüman | Kısa Yol | Tür | Varsayılan | Açıklama |
| :--- | :--- | :--- | :--- | :--- |
| `--input` | `-i` | `str` | `reports/experiments.json` | Analiz edilip grafiğe dökülecek deney verisi JSON dosyası yolu. |

---

## 📊 Deney Çalıştırma ve Analiz

Sistemdeki parametrelerin (paket boyutu, timeout, kayıp oranı, dosya boyutu) performans metrikleri (throughput, retransmission oranı, goodput, tamamlama süresi) üzerindeki etkilerini incelemek için otomatik bir deney düzeneği kurulmuştur.

Deneyleri çalıştırıp analiz grafiklerini üretmek için sırasıyla şu komutları uygulayın:

```bash
# 1. Deneyleri otomatik olarak koştur (reports/experiments.json üretir)
python run_experiments.py

# 2. Deney verilerini okuyarak 4 adet performans grafiği çiz (reports/ klasörüne kaydeder)
python analyze.py
```

**Üretilen Grafikler (`reports/` altında):**
*   `throughput_vs_chunksize.png`: Chunk boyutunun Throughput (KB/s) üzerindeki etkisi.
*   `retransmission_vs_timeout.png`: Timeout süresinin Yeniden Gönderim Oranına (%) etkisi.
*   `goodput_vs_lossrate.png`: Ağdaki paket kayıp oranının Goodput (KB/s) üzerindeki etkisi.
*   `completion_vs_filesize.png`: Aktarılan dosya boyutunun dosya aktarım süresi (saniye) üzerindeki etkisi.

---

## 📂 Dosya Yapısı Ağacı

```text
netprobe/
├── __init__.py
├── logger.py            # Event-based JSONL ve konsol günlükçüsü
├── packet.py            # Veri ve ACK paketlerinin byte paketleme/çözme işlemleri
├── protocol.py          # Genel protokol ayarları, MD5 kontrolü, dosya parçalama/birleştirme
├── receiver.py          # Alıcı (Receiver) protokol döngüleri (SAW, GBN)
├── sender.py            # Gönderici (Sender) sliding-window ve timeout döngüleri (SAW, GBN)
└── stats.py             # RTT, Throughput, Goodput hesaplayıcı ve rapor basıcı
simulator/
├── __init__.py
└── network_emulator.py  # Paket kaybı ve gecikme emülasyonu sağlayan soket sarmalayıcı
tests/
├── test_integration_cli.py  # İstemci ve sunucu arası CLI entegrasyon testleri
├── test_loopback_gbn.py      # GBN modu loopback bütünlük testi
├── test_loopback_saw.py      # SAW modu loopback bütünlük testi
├── test_packet.py            # Paket serileştirme ve checksum birim testleri
└── test_stats.py             # İstatistik hesaplama ve RTT birim testleri
analyze.py               # Deney sonuçlarını okuyarak grafik üreten analiz betiği
client.py                # İstemci (gönderici) giriş noktası
config.py                # Sabitler ve varsayılan parametre yapılandırması
run_experiments.py       # Çoklu senaryoları otomatik çalıştıran test koşucu
server.py                # Sunucu (alıcı) giriş noktası
requirements.txt         # Harici kütüphane listesi
.gitignore               # Git dışı bırakma kuralları
README.md                # Proje tanıtım ve kılavuz dokümanı
logs/
└── .gitkeep             # Klasörün Git'te tutulmasını sağlayan boş dosya
reports/
└── .gitkeep             # Klasörün Git'te tutulmasını sağlayan boş dosya
```



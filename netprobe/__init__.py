# netprobe/__init__.py
"""
netprobe
========
NetProbe paketinin kök modülü.

Bu paket UDP üzerinde güvenilir dosya aktarımı sağlayan tüm bileşenleri içerir:
  - packet   : Paket tanımları ve binary serializasyon
  - logger   : Olay kayıt sistemi
  - stats    : Performans analizi
  - protocol : Protokol motor parametreleri
  - sender   : Gönderici (sliding window)
  - receiver : Alıcı (buffer yönetimi + ACK)

Kullanım:
    from netprobe.packet import DataPacket, AckPacket
    from netprobe.logger import NetLogger
    from netprobe.stats  import StatsCollector
"""

__version__ = "1.0.0"
__author__ = "BTU Bilgisayar Ağları"

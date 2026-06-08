"""
netprobe/packet.py
==================
NetProbe — UDP Tabanlı Güvenilir Dosya Aktarım Sistemi
Bursa Teknik Üniversitesi | Bilgisayar Ağları Dersi

Bu modül, ağ üzerinden iletilen her paket tipini tanımlar.
Tüm binary kodlama/çözme işlemleri burada gerçekleşir.

Paket Formatları
----------------
DATA Paketi:
  [ TYPE:1 | SEQ_NUM:4 | TOTAL_PACKETS:4 | PAYLOAD_LEN:2 | CHECKSUM:2 | PAYLOAD:0-1024 ]
  struct format : "! B I I H H" → 13 byte sabit başlık
  Toplam max   : 13 + 1024 = 1037 byte

ACK Paketi:
  [ TYPE:1 | ACK_NUM:4 | STATUS:1 | RECV_WINDOW:2 | CHECKSUM:2 ]
  struct format : "! B I B H H" → 10 byte sabit (payload yok)

Tip Sabitleri:
  TYPE_DATA    = 0x01
  TYPE_ACK     = 0x02
  TYPE_FIN     = 0x03
  TYPE_FIN_ACK = 0x04

Status Sabitleri (ACK):
  STATUS_OK          = 0x00  → Paket başarıyla alındı
  STATUS_NAK         = 0x01  → Hatalı / sıra dışı paket
  STATUS_BUFFER_FULL = 0xFF  → Alıcı tamponu dolu
"""

import struct
import zlib
from dataclasses import dataclass, field
from typing import Tuple


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

# Paket tip kodları
TYPE_DATA: int = 0x01
TYPE_ACK: int = 0x02
TYPE_FIN: int = 0x03
TYPE_FIN_ACK: int = 0x04

# ACK durum kodları
STATUS_OK: int = 0x00
STATUS_NAK: int = 0x01
STATUS_BUFFER_FULL: int = 0xFF

# struct format string'leri (big-endian)
_DATA_HEADER_FMT: str = "! B I I H H"   # TYPE, SEQ_NUM, TOTAL_PACKETS, PAYLOAD_LEN, CHECKSUM
_ACK_HEADER_FMT: str = "! B I B H H"    # TYPE, ACK_NUM, STATUS, RECV_WINDOW, CHECKSUM

# Sabit başlık boyutları (byte)
DATA_HEADER_SIZE: int = struct.calcsize(_DATA_HEADER_FMT)  # 13 byte
ACK_HEADER_SIZE: int = struct.calcsize(_ACK_HEADER_FMT)   # 10 byte

# Maksimum payload boyutu: UDP datagram max (65535) - IP(20) - UDP(8) - DATA_HEADER(13)
MAX_PAYLOAD_SIZE: int = 65494


# ---------------------------------------------------------------------------
# CRC-16 Yardımcı Fonksiyonları
# ---------------------------------------------------------------------------

def compute_checksum(data: bytes) -> int:
    """
    Verilen byte dizisi üzerinde CRC-32 tabanlı 16-bit checksum hesaplar.

    Uygulama katmanında bütünlük doğrulaması için kullanılır; UDP'nin
    kendi checksum'ının isteğe bağlı olduğu durumlarda bu fonksiyon
    ek bir güvence sağlar.

    Algoritma:
        Python'un zlib.crc32 ile CRC-32 değeri hesaplanır, ardından
        alt 16 biti (& 0xFFFF) alınarak 2 byte'a sığdırılır.

    Args:
        data (bytes): Checksum hesaplanacak ham veri.

    Returns:
        int: 0–65535 arasında 16-bit checksum değeri.

    Örnek:
        >>> compute_checksum(b"hello")
        907060870 & 0xFFFF  # → gerçek değer çalışma zamanında hesaplanır
    """
    return zlib.crc32(data) & 0xFFFF


def verify_checksum(data: bytes, expected: int) -> bool:
    """
    Hesaplanan checksum'ı beklenen değerle karşılaştırır.

    Args:
        data     (bytes): Kontrol edilecek ham veri.
        expected (int)  : Paketin başlığında taşınan checksum değeri.

    Returns:
        bool: Eşleşiyorsa True, bozulma tespit edilirse False.

    Örnek:
        >>> raw = b"test payload"
        >>> cs  = compute_checksum(raw)
        >>> verify_checksum(raw, cs)
        True
        >>> verify_checksum(raw, cs ^ 0xFFFF)  # bozulmuş checksum
        False
    """
    return compute_checksum(data) == expected


# ---------------------------------------------------------------------------
# DataPacket
# ---------------------------------------------------------------------------

@dataclass
class DataPacket:
    """
    UDP üzerinden gönderilen veri paketi.

    Attributes:
        seq_num        (int)  : Paketin sıra numarası (0'dan başlar).
        total_packets  (int)  : Aktarımdaki toplam paket sayısı.
                                İlk paketle alıcı dosya büyüklüğünü öğrenir.
        payload        (bytes): Taşınan ham dosya verisi (max 1024 byte).
        pkt_type       (int)  : Paket tipi; varsayılan TYPE_DATA (0x01).
                                FIN paketi için TYPE_FIN (0x03) kullanılır.

    Sabit Başlık Boyutu:
        13 byte  →  TYPE(1) + SEQ_NUM(4) + TOTAL_PACKETS(4) +
                    PAYLOAD_LEN(2) + CHECKSUM(2)

    Örnek:
        >>> pkt = DataPacket(seq_num=0, total_packets=100, payload=b"abc")
        >>> raw = pkt.to_bytes()
        >>> restored = DataPacket.from_bytes(raw)
        >>> restored.seq_num
        0
    """

    seq_num: int
    total_packets: int
    payload: bytes = field(default=b"")
    pkt_type: int = field(default=TYPE_DATA)

    # ------------------------------------------------------------------
    # Doğrulama
    # ------------------------------------------------------------------

    def __post_init__(self) -> None:
        """Alanları aralık kontrolüne tabi tutar."""
        if not (0 <= self.seq_num <= 0xFFFF_FFFF):
            raise ValueError(f"seq_num aralık dışı: {self.seq_num}")
        if not (0 <= self.total_packets <= 0xFFFF_FFFF):
            raise ValueError(f"total_packets aralık dışı: {self.total_packets}")
        if len(self.payload) > MAX_PAYLOAD_SIZE:
            raise ValueError(
                f"payload çok büyük: {len(self.payload)} byte "
                f"(max {MAX_PAYLOAD_SIZE})"
            )
        if self.pkt_type not in (TYPE_DATA, TYPE_FIN):
            raise ValueError(f"Geçersiz DataPacket tipi: 0x{self.pkt_type:02X}")

    # ------------------------------------------------------------------
    # Serializasyon
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """
        Paketi ağ üzerinden gönderilebilecek ham byte dizisine dönüştürür.

        Adımlar:
            1. payload_len hesaplanır.
            2. Checksum alanı sıfırlanmış başlık + payload birleştirilir.
            3. CRC-16 hesaplanır.
            4. Gerçek checksum değeri başlığa yerleştirilir.
            5. Başlık + payload birleştirilerek döndürülür.

        Returns:
            bytes: Gönderilmeye hazır ham paket (max 1037 byte).

        Raises:
            struct.error: Herhangi bir alan 'struct' aralığını aşarsa.
        """
        payload_len = len(self.payload)

        # Checksum hesaplamak için önce sıfırla doldurulmuş başlık oluştur
        header_no_crc = struct.pack(
            _DATA_HEADER_FMT,
            self.pkt_type,
            self.seq_num,
            self.total_packets,
            payload_len,
            0,  # checksum alanı henüz boş
        )
        checksum = compute_checksum(header_no_crc + self.payload)

        # Gerçek başlığı checksum ile oluştur
        header = struct.pack(
            _DATA_HEADER_FMT,
            self.pkt_type,
            self.seq_num,
            self.total_packets,
            payload_len,
            checksum,
        )
        return header + self.payload

    # ------------------------------------------------------------------
    # Deserializasyon
    # ------------------------------------------------------------------

    @classmethod
    def from_bytes(cls, raw: bytes) -> "DataPacket":
        """
        Ham byte dizisini DataPacket nesnesine dönüştürür ve checksum'ı doğrular.

        Args:
            raw (bytes): Soket üzerinden alınan ham veri.

        Returns:
            DataPacket: Ayrıştırılmış paket nesnesi.

        Raises:
            ValueError: Paket çok kısa, tip uyumsuz veya checksum hatalıysa.

        Örnek:
            >>> raw = DataPacket(seq_num=1, total_packets=10, payload=b"X"*512).to_bytes()
            >>> pkt = DataPacket.from_bytes(raw)
            >>> pkt.seq_num
            1
        """
        if len(raw) < DATA_HEADER_SIZE:
            raise ValueError(
                f"Paket çok kısa: {len(raw)} byte (min {DATA_HEADER_SIZE})"
            )

        pkt_type, seq_num, total_packets, payload_len, received_crc = struct.unpack(
            _DATA_HEADER_FMT, raw[:DATA_HEADER_SIZE]
        )

        if pkt_type not in (TYPE_DATA, TYPE_FIN):
            raise ValueError(f"Beklenen DATA/FIN, alınan tip: 0x{pkt_type:02X}")

        payload = raw[DATA_HEADER_SIZE: DATA_HEADER_SIZE + payload_len]

        # Checksum doğrulama: alınan CRC çıkartılıp sıfırla tekrar hesaplanır
        header_no_crc = struct.pack(
            _DATA_HEADER_FMT,
            pkt_type,
            seq_num,
            total_packets,
            payload_len,
            0,
        )
        if not verify_checksum(header_no_crc + payload, received_crc):
            raise ValueError(
                f"Checksum hatası — SEQ={seq_num}, "
                f"beklenen=0x{compute_checksum(header_no_crc + payload):04X}, "
                f"alınan=0x{received_crc:04X}"
            )

        return cls(
            seq_num=seq_num,
            total_packets=total_packets,
            payload=payload,
            pkt_type=pkt_type,
        )

    # ------------------------------------------------------------------
    # Yardımcı Özellikler
    # ------------------------------------------------------------------

    @property
    def is_fin(self) -> bool:
        """Paketin FIN paketi olup olmadığını döndürür."""
        return self.pkt_type == TYPE_FIN

    @property
    def size(self) -> int:
        """Paketin toplam boyutunu (başlık + payload) byte cinsinden döndürür."""
        return DATA_HEADER_SIZE + len(self.payload)

    def __repr__(self) -> str:
        type_name = {TYPE_DATA: "DATA", TYPE_FIN: "FIN"}.get(self.pkt_type, "?")
        return (
            f"DataPacket(type={type_name}, seq={self.seq_num}, "
            f"total={self.total_packets}, payload={len(self.payload)}B)"
        )


# ---------------------------------------------------------------------------
# AckPacket
# ---------------------------------------------------------------------------

@dataclass
class AckPacket:
    """
    Alıcının gönderdiği onay (acknowledgement) paketi.

    Attributes:
        ack_num     (int): Onaylanan sıra numarası.
                          GBN modunda cumulative (birikimli) ACK;
                          SR modunda individual (bireysel) ACK.
        status      (int): Yanıt durumu kodu.
                          STATUS_OK (0x00), STATUS_NAK (0x01),
                          STATUS_BUFFER_FULL (0xFF).
        recv_window (int): Alıcının boş buffer kapasitesi (flow control).
                          0 ise gönderici beklemeli (zero-window probe).
        pkt_type    (int): Paket tipi; varsayılan TYPE_ACK (0x02).
                          Bağlantı sonunda TYPE_FIN_ACK (0x04) kullanılır.

    Sabit Boyut:
        10 byte → TYPE(1) + ACK_NUM(4) + STATUS(1) + RECV_WINDOW(2) + CHECKSUM(2)

    Örnek:
        >>> ack = AckPacket(ack_num=5, status=STATUS_OK, recv_window=8)
        >>> raw = ack.to_bytes()
        >>> restored = AckPacket.from_bytes(raw)
        >>> restored.ack_num
        5
    """

    ack_num: int
    status: int = STATUS_OK
    recv_window: int = 0
    pkt_type: int = field(default=TYPE_ACK)

    # ------------------------------------------------------------------
    # Doğrulama
    # ------------------------------------------------------------------

    def __post_init__(self) -> None:
        """Alanları aralık kontrolüne tabi tutar."""
        if not (0 <= self.ack_num <= 0xFFFF_FFFF):
            raise ValueError(f"ack_num aralık dışı: {self.ack_num}")
        if self.status not in (STATUS_OK, STATUS_NAK, STATUS_BUFFER_FULL):
            raise ValueError(f"Geçersiz status kodu: 0x{self.status:02X}")
        if not (0 <= self.recv_window <= 0xFFFF):
            raise ValueError(f"recv_window aralık dışı: {self.recv_window}")
        if self.pkt_type not in (TYPE_ACK, TYPE_FIN_ACK):
            raise ValueError(f"Geçersiz AckPacket tipi: 0x{self.pkt_type:02X}")

    # ------------------------------------------------------------------
    # Serializasyon
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """
        ACK paketini ağ üzerinden gönderilebilecek ham byte dizisine dönüştürür.

        Adımlar:
            1. Checksum alanı sıfırlanmış başlık oluşturulur.
            2. CRC-16 hesaplanır.
            3. Gerçek checksum ile başlık yeniden paketlenir.

        Returns:
            bytes: 10 byte sabit uzunlukta ham ACK paketi.
        """
        header_no_crc = struct.pack(
            _ACK_HEADER_FMT,
            self.pkt_type,
            self.ack_num,
            self.status,
            self.recv_window,
            0,  # checksum alanı henüz boş
        )
        checksum = compute_checksum(header_no_crc)

        return struct.pack(
            _ACK_HEADER_FMT,
            self.pkt_type,
            self.ack_num,
            self.status,
            self.recv_window,
            checksum,
        )

    # ------------------------------------------------------------------
    # Deserializasyon
    # ------------------------------------------------------------------

    @classmethod
    def from_bytes(cls, raw: bytes) -> "AckPacket":
        """
        Ham byte dizisini AckPacket nesnesine dönüştürür ve checksum'ı doğrular.

        Args:
            raw (bytes): Soket üzerinden alınan ham ACK verisi.

        Returns:
            AckPacket: Ayrıştırılmış ACK nesnesi.

        Raises:
            ValueError: Paket çok kısa, tip uyumsuz veya checksum hatalıysa.

        Örnek:
            >>> raw = AckPacket(ack_num=3, status=STATUS_OK, recv_window=4).to_bytes()
            >>> ack = AckPacket.from_bytes(raw)
            >>> ack.ack_num
            3
        """
        if len(raw) < ACK_HEADER_SIZE:
            raise ValueError(
                f"ACK paketi çok kısa: {len(raw)} byte (min {ACK_HEADER_SIZE})"
            )

        pkt_type, ack_num, status, recv_window, received_crc = struct.unpack(
            _ACK_HEADER_FMT, raw[:ACK_HEADER_SIZE]
        )

        if pkt_type not in (TYPE_ACK, TYPE_FIN_ACK):
            raise ValueError(f"Beklenen ACK/FIN-ACK, alınan tip: 0x{pkt_type:02X}")

        # Checksum doğrulama
        header_no_crc = struct.pack(
            _ACK_HEADER_FMT,
            pkt_type,
            ack_num,
            status,
            recv_window,
            0,
        )
        if not verify_checksum(header_no_crc, received_crc):
            raise ValueError(
                f"ACK checksum hatası — ACK_NUM={ack_num}, "
                f"beklenen=0x{compute_checksum(header_no_crc):04X}, "
                f"alınan=0x{received_crc:04X}"
            )

        return cls(
            ack_num=ack_num,
            status=status,
            recv_window=recv_window,
            pkt_type=pkt_type,
        )

    # ------------------------------------------------------------------
    # Yardımcı Özellikler
    # ------------------------------------------------------------------

    @property
    def is_fin_ack(self) -> bool:
        """Paketin FIN-ACK paketi olup olmadığını döndürür."""
        return self.pkt_type == TYPE_FIN_ACK

    @property
    def is_nak(self) -> bool:
        """Paketin negatif onay (NAK) olup olmadığını döndürür."""
        return self.status == STATUS_NAK

    @property
    def is_buffer_full(self) -> bool:
        """Alıcı tamponunun dolu olup olmadığını gösterir."""
        return self.status == STATUS_BUFFER_FULL

    def __repr__(self) -> str:
        type_name = {TYPE_ACK: "ACK", TYPE_FIN_ACK: "FIN-ACK"}.get(self.pkt_type, "?")
        status_name = {
            STATUS_OK: "OK",
            STATUS_NAK: "NAK",
            STATUS_BUFFER_FULL: "BUFFER_FULL",
        }.get(self.status, f"0x{self.status:02X}")
        return (
            f"AckPacket(type={type_name}, ack_num={self.ack_num}, "
            f"status={status_name}, window={self.recv_window})"
        )


# ---------------------------------------------------------------------------
# Yardımcı Fabrika Fonksiyonları
# ---------------------------------------------------------------------------

def make_fin_packet(seq_num: int, total_packets: int) -> DataPacket:
    """
    FIN paketi oluşturur. Payload içermez; aktarımın sona erdiğini bildirir.

    Args:
        seq_num       (int): Aktarımdaki son sıra numarası + 1.
        total_packets (int): Aktarımdaki toplam paket sayısı.

    Returns:
        DataPacket: pkt_type=TYPE_FIN, payload=b"" olan paket.
    """
    return DataPacket(
        seq_num=seq_num,
        total_packets=total_packets,
        payload=b"",
        pkt_type=TYPE_FIN,
    )


def make_fin_ack_packet(ack_num: int) -> AckPacket:
    """
    FIN-ACK paketi oluşturur. Alıcının aktarımı onayladığını bildirir.

    Args:
        ack_num (int): Onaylanan FIN paketinin sıra numarası.

    Returns:
        AckPacket: pkt_type=TYPE_FIN_ACK olan paket.
    """
    return AckPacket(
        ack_num=ack_num,
        status=STATUS_OK,
        recv_window=0,
        pkt_type=TYPE_FIN_ACK,
    )


def make_nak_packet(expected_seq: int, recv_window: int = 0) -> AckPacket:
    """
    NAK (negatif onay) paketi oluşturur.

    Checksum hatası veya sıra dışı paket alındığında alıcı tarafından gönderilir.

    Args:
        expected_seq (int): Alıcının beklediği sıra numarası.
        recv_window  (int): Mevcut boş buffer kapasitesi.

    Returns:
        AckPacket: status=STATUS_NAK olan paket.
    """
    return AckPacket(
        ack_num=expected_seq,
        status=STATUS_NAK,
        recv_window=recv_window,
        pkt_type=TYPE_ACK,
    )


# ---------------------------------------------------------------------------
# Paket Tipi Tanımlama Yardımcısı
# ---------------------------------------------------------------------------

def identify_packet(raw: bytes) -> Tuple[str, int]:
    """
    Ham byte dizisinin ilk byte'ına bakarak paket tipini tanımlar.

    Gerçek bir paket parse etmeden önce hangi sınıfla ayrıştırma
    yapılacağını belirlemek için kullanılır.

    Args:
        raw (bytes): Soket üzerinden alınan ham veri.

    Returns:
        Tuple[str, int]: ("DATA" | "ACK" | "FIN" | "FIN_ACK" | "UNKNOWN", tip_kodu)

    Raises:
        ValueError: Ham veri boşsa.

    Örnek:
        >>> pkt = DataPacket(seq_num=0, total_packets=1, payload=b"x")
        >>> identify_packet(pkt.to_bytes())
        ('DATA', 1)
    """
    if not raw:
        raise ValueError("Boş ham veri — paket tipi tanımlanamıyor.")

    type_byte = raw[0]
    names = {
        TYPE_DATA: "DATA",
        TYPE_ACK: "ACK",
        TYPE_FIN: "FIN",
        TYPE_FIN_ACK: "FIN_ACK",
    }
    return names.get(type_byte, "UNKNOWN"), type_byte

# -*- coding: utf-8 -*-
"""
netprobe/logger.py
==================
NetProbe — UDP Tabanlı Güvenilir Dosya Aktarım Sistemi
Bursa Teknik Üniversitesi | Bilgisayar Ağları Dersi

Olay kayıt (event log) sistemi.

Bu modül ağ aktarımı sırasında gerçekleşen tüm olayları;
    - Renkli ve okunabilir formatta konsola,
    - Satır başına bir JSON nesnesi (JSONL) olarak dosyaya
  eş zamanlı yazar.

``stats.py`` modülü, ``get_events()`` metoduyla bu kayıtlara
programatik olarak erişerek performans metriklerini hesaplar.

Olay Tipleri:
    SEND       → Paket gönderildi
    ACK_RECV   → ACK alındı
    TIMEOUT    → Timeout tetiklendi
    RETRANSMIT → Paket yeniden gönderildi
    DROP       → Simülatör paketi düşürdü
    ERROR      → Checksum veya protokol hatası
    FIN        → Aktarım tamamlandı

Log Seviyeleri:
    DEBUG → Her olayı ayrıntılı şekilde yazar (geliştirme için)
    INFO  → Tüm olayları yazar (normal kullanım)
    WARN  → Yalnızca TIMEOUT, RETRANSMIT, DROP, ERROR, FIN yazar

Log dosyası:
    logs/transfer_<YYYY-MM-DD_HH-MM-SS>.jsonl
"""

import json
import os
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Dict, List, Optional

import config


# ---------------------------------------------------------------------------
# Renk Kodları (ANSI — Windows'ta da çalışır, Python 3.6+)
# ---------------------------------------------------------------------------

class _Color:
    """ANSI renk kodu sabitleri. Konsol çıktısını renklendirmek için kullanılır."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    CYAN    = "\033[96m"    # SEND
    GREEN   = "\033[92m"    # ACK_RECV
    YELLOW  = "\033[93m"    # TIMEOUT / RETRANSMIT
    RED     = "\033[91m"    # DROP / ERROR
    MAGENTA = "\033[95m"    # FIN
    WHITE   = "\033[97m"    # genel


# Windows konsolunda ANSI desteği aç ve UTF-8 stdout zorla
if sys.platform == "win32":
    os.system("")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# EventType — Olay Tipleri
# ---------------------------------------------------------------------------

class EventType(Enum):
    """
    Protokol boyunca kaydedilen olay tiplerini tanımlar.

    Değerler:
        SEND       : Bir DATA paketi gönderildiğinde tetiklenir.
        ACK_RECV   : Bir ACK paketi alındığında tetiklenir.
        TIMEOUT    : Bir ACK için bekleme süresi dolduğunda tetiklenir.
        RETRANSMIT : Bir paket yeniden gönderildiğinde tetiklenir.
        DROP       : Simülatör bir paketi düşürdüğünde tetiklenir.
        ERROR      : Checksum veya protokol hatası oluştuğunda tetiklenir.
        FIN        : Aktarım başarıyla tamamlandığında tetiklenir.
    """
    SEND       = auto()
    ACK_RECV   = auto()
    TIMEOUT    = auto()
    RETRANSMIT = auto()
    DROP       = auto()
    ERROR      = auto()
    FIN        = auto()


# ---------------------------------------------------------------------------
# LOG_LEVEL → EventType filtresi
# ---------------------------------------------------------------------------

# Her seviyede hangi olayların yazılacağını belirler.
_LEVEL_FILTER: Dict[str, set] = {
    "DEBUG": {
        EventType.SEND, EventType.ACK_RECV, EventType.TIMEOUT,
        EventType.RETRANSMIT, EventType.DROP, EventType.ERROR, EventType.FIN
    },
    "INFO": {
        EventType.SEND, EventType.ACK_RECV, EventType.TIMEOUT,
        EventType.RETRANSMIT, EventType.DROP, EventType.ERROR, EventType.FIN
    },
    "WARN": {
        EventType.TIMEOUT, EventType.RETRANSMIT,
        EventType.DROP, EventType.ERROR, EventType.FIN
    },
}

# Konsola yazdırırken DEBUG seviyesinde ek detay göster
_DEBUG_DETAIL_EVENTS = {EventType.SEND, EventType.ACK_RECV}

# Her olay tipi için konsol rengi ve kısa etiket
_EVENT_STYLE: Dict[EventType, tuple] = {
    EventType.SEND:       (_Color.CYAN,    "SEND      "),
    EventType.ACK_RECV:   (_Color.GREEN,   "ACK_RECV  "),
    EventType.TIMEOUT:    (_Color.YELLOW,  "TIMEOUT   "),
    EventType.RETRANSMIT: (_Color.YELLOW,  "RETRANSMIT"),
    EventType.DROP:       (_Color.RED,     "DROP      "),
    EventType.ERROR:      (_Color.RED,     "ERROR     "),
    EventType.FIN:        (_Color.MAGENTA, "FIN       "),
}


# ---------------------------------------------------------------------------
# LogEntry — Tek Bir Olay Kaydı
# ---------------------------------------------------------------------------

@dataclass
class LogEntry:
    """
    Tek bir protokol olayını temsil eden değişmez veri nesnesi.

    Bu nesneler ``get_events()`` metoduyla sorgulanır ve ``stats.py``
    tarafından performans hesaplamalarında kullanılır.

    Attributes:
        timestamp   (float)    : Olayın gerçekleştiği Unix zaman damgası (saniye).
        event_type  (EventType): Olayın türü (bkz. EventType enum).
        seq_num     (int)      : İlgili paketin sıra numarası.
                                 Geçerli değilse -1 kullanılır (örn. FIN olayı).
        details     (dict)     : Olaya özgü ek bilgiler (rtt_ms, attempt, vb.).
    """
    timestamp:  float
    event_type: EventType
    seq_num:    int
    details:    Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        LogEntry'yi JSON'a serileştirilebilir bir sözlüğe dönüştürür.

        Returns:
            dict: timestamp, event_type (string), seq_num, details anahtarlarını içerir.
        """
        return {
            "timestamp":  self.timestamp,
            "event_type": self.event_type.name,
            "seq_num":    self.seq_num,
            "details":    self.details,
        }

    @property
    def human_time(self) -> str:
        """Zaman damgasını insan okunabilir ISO-8601 formatına çevirir."""
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).strftime(
            "%H:%M:%S.%f"
        )[:-3]  # milisaniye hassasiyeti


# ---------------------------------------------------------------------------
# NetLogger — Ana Logger Sınıfı
# ---------------------------------------------------------------------------

class NetLogger:
    """
    NetProbe olay kayıt sistemi.

    Aktarım sırasında gerçekleşen tüm olayları (SEND, ACK, TIMEOUT, vb.)
    eş zamanlı olarak konsola ve JSONL log dosyasına yazar. Thread-safe'dir.

    Kullanım:
        >>> logger = NetLogger()
        >>> logger.log_send(seq_num=0, size=1024)
        >>> logger.log_ack(seq_num=0, rtt_ms=12.5)
        >>> logger.log_fin(total_time_s=3.7)
        >>> logger.close()

    Attributes:
        log_path (str): Yazılan JSONL dosyasının yolu.
    """

    def __init__(
        self,
        log_dir: str = config.LOG_DIR,
        log_level: str = config.LOG_LEVEL,
    ) -> None:
        """
        Logger'ı başlatır, log klasörünü oluşturur ve dosyayı açar.

        Args:
            log_dir   (str): Log dosyalarının kaydedileceği klasör.
                             Varsayılan: config.LOG_DIR ("logs").
            log_level (str): Filtreleme seviyesi ("DEBUG", "INFO", "WARN").
                             Varsayılan: config.LOG_LEVEL.

        Raises:
            ValueError: Geçersiz log_level verilirse.
        """
        if log_level not in _LEVEL_FILTER:
            raise ValueError(
                f"Geçersiz log seviyesi: '{log_level}'. "
                f"Geçerli seçenekler: {list(_LEVEL_FILTER.keys())}"
            )

        self._level   = log_level
        self._allowed = _LEVEL_FILTER[log_level]
        self._events: List[LogEntry] = []
        self._lock   = threading.Lock()

        # Log dosyasını oluştur
        os.makedirs(log_dir, exist_ok=True)
        ts_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.log_path = os.path.join(log_dir, f"transfer_{ts_str}.jsonl")
        self._file = open(self.log_path, "w", encoding="utf-8")

        # Başlangıç bilgisi
        self._console_header()

    # ------------------------------------------------------------------
    # Temel log metodu
    # ------------------------------------------------------------------

    def log(
        self,
        event_type: EventType,
        seq_num: int = -1,
        **kwargs: Any,
    ) -> None:
        """
        Bir olayı kaydeder.

        Seviye filtresini geçen olaylar hem ``_events`` listesine,
        hem konsola hem de JSONL dosyasına yazılır.

        Args:
            event_type (EventType): Kaydedilecek olay tipi.
            seq_num    (int)      : İlgili paketin sıra numarası. Yoksa -1.
            **kwargs              : Olaya özgü ek alanlar (rtt_ms, attempt, vb.).
        """
        if event_type not in self._allowed:
            return

        entry = LogEntry(
            timestamp  = datetime.now(tz=timezone.utc).timestamp(),
            event_type = event_type,
            seq_num    = seq_num,
            details    = dict(kwargs),
        )

        with self._lock:
            self._events.append(entry)
            self._write_jsonl(entry)
            self._write_console(entry)

    # ------------------------------------------------------------------
    # Kısayol metodları
    # ------------------------------------------------------------------

    def log_send(self, seq_num: int, size: int) -> None:
        """
        Paket gönderme olayını kaydeder.

        Args:
            seq_num (int): Gönderilen paketin sıra numarası.
            size    (int): Paketin toplam boyutu (byte, başlık dahil).
        """
        self.log(EventType.SEND, seq_num=seq_num, size_bytes=size)

    def log_ack(self, seq_num: int, rtt_ms: float) -> None:
        """
        ACK alma olayını kaydeder.

        Args:
            seq_num (int)  : Onaylanan sıra numarası.
            rtt_ms  (float): Bu ACK için ölçülen Round-Trip Time (milisaniye).
        """
        self.log(EventType.ACK_RECV, seq_num=seq_num, rtt_ms=round(rtt_ms, 3))

    def log_timeout(self, seq_num: int, attempt: int) -> None:
        """
        Timeout olayını kaydeder.

        Args:
            seq_num (int): Timeout gerçekleşen paketin sıra numarası.
            attempt (int): Bu paket için kaçıncı timeout denemesi olduğu.
        """
        self.log(EventType.TIMEOUT, seq_num=seq_num, attempt=attempt)

    def log_retransmit(self, seq_num: int, attempt: int) -> None:
        """
        Yeniden gönderme olayını kaydeder.

        Args:
            seq_num (int): Yeniden gönderilen paketin sıra numarası.
            attempt (int): Kaçıncı yeniden gönderme denemesi olduğu.
        """
        self.log(EventType.RETRANSMIT, seq_num=seq_num, attempt=attempt)

    def log_drop(self, seq_num: int) -> None:
        """
        Simülatörün paket düşürme olayını kaydeder.

        Args:
            seq_num (int): Düşürülen paketin sıra numarası.
        """
        self.log(EventType.DROP, seq_num=seq_num)

    def log_error(self, seq_num: int, expected: Any, got: Any) -> None:
        """
        Checksum veya protokol hatasını kaydeder.

        Args:
            seq_num  (int): Hatalı paketin sıra numarası.
            expected (Any): Beklenen değer (checksum, seq_num, vb.).
            got      (Any): Gerçekte alınan değer.
        """
        self.log(
            EventType.ERROR,
            seq_num=seq_num,
            expected=str(expected),
            got=str(got),
        )

    def log_fin(self, total_time_s: float) -> None:
        """
        Aktarım tamamlanma olayını kaydeder.

        Args:
            total_time_s (float): Aktarımın toplam süresi (saniye).
        """
        self.log(
            EventType.FIN,
            seq_num=-1,
            total_time_s=round(total_time_s, 6),
        )

    # ------------------------------------------------------------------
    # Sorgulama
    # ------------------------------------------------------------------

    def get_events(self, event_type: Optional[EventType] = None) -> List[LogEntry]:
        """
        Kaydedilen olayları döndürür.

        Args:
            event_type (EventType | None): Filtrelenecek olay tipi.
                                           None verilirse tüm olaylar döner.

        Returns:
            List[LogEntry]: Eşleşen olay kayıtlarının listesi.

        Örnek:
            >>> rtt_events = logger.get_events(EventType.ACK_RECV)
            >>> send_events = logger.get_events(EventType.SEND)
            >>> all_events  = logger.get_events()
        """
        with self._lock:
            if event_type is None:
                return list(self._events)
            return [e for e in self._events if e.event_type == event_type]

    # ------------------------------------------------------------------
    # Kapatma
    # ------------------------------------------------------------------

    def close(self) -> None:
        """
        Log dosyasını güvenli biçimde kapatır.

        Aktarım tamamlandıktan sonra çağrılmalıdır.
        Dosya zaten kapalıysa sessizce devam eder.
        """
        with self._lock:
            if not self._file.closed:
                self._file.flush()
                self._file.close()
                print(
                    f"\n{_Color.WHITE}[NetProbe] Log dosyası kaydedildi: "
                    f"{_Color.BOLD}{self.log_path}{_Color.RESET}"
                )

    # ------------------------------------------------------------------
    # Dahili yazma yardımcıları
    # ------------------------------------------------------------------

    def _write_jsonl(self, entry: LogEntry) -> None:
        """Log girişini JSONL dosyasına yazar (kilit dışarıda tutulur)."""
        line = json.dumps(entry.to_dict(), ensure_ascii=False)
        self._file.write(line + "\n")
        self._file.flush()

    def _write_console(self, entry: LogEntry) -> None:
        """Log girişini renkli formatta konsola yazar (kilit dışarıda tutulur)."""
        color, label = _EVENT_STYLE.get(entry.event_type, (_Color.WHITE, "UNKNOWN   "))

        # Temel satır
        seq_str = f"SEQ={entry.seq_num:>6}" if entry.seq_num >= 0 else " " * 10

        # Ayrıntı dizesi
        detail_parts = []
        for k, v in entry.details.items():
            if isinstance(v, float):
                detail_parts.append(f"{k}={v:.3f}")
            else:
                detail_parts.append(f"{k}={v}")
        detail_str = "  " + "  ".join(detail_parts) if detail_parts else ""

        # DEBUG modunda ek bilgi
        extra = ""
        if self._level == "DEBUG" and entry.event_type in _DEBUG_DETAIL_EVENTS:
            extra = f"  [{entry.human_time}]"

        line = (
            f"{color}{_Color.BOLD}[{label}]{_Color.RESET}"
            f"  {_Color.WHITE}{entry.human_time}{_Color.RESET}"
            f"  {seq_str}"
            f"{detail_str}"
            f"{extra}"
        )
        print(line)

    def _console_header(self) -> None:
        """Logger başlatıldığında konsola bilgi başlığı yazdırır."""
        border = "=" * 60
        print(f"\n{_Color.BOLD}{_Color.CYAN}{border}{_Color.RESET}")
        print(
            f"{_Color.BOLD}{_Color.CYAN}"
            f"  NetProbe Logger  |  Seviye: {self._level}"
            f"{_Color.RESET}"
        )
        print(f"{_Color.BOLD}{_Color.CYAN}{border}{_Color.RESET}\n")

    # ------------------------------------------------------------------
    # Context manager desteği
    # ------------------------------------------------------------------

    def __enter__(self) -> "NetLogger":
        """``with NetLogger() as logger:`` sözdizimini destekler."""
        return self

    def __exit__(self, *_: Any) -> None:
        """Blok sonunda log dosyasını otomatik kapatır."""
        self.close()

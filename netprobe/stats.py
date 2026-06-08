# -*- coding: utf-8 -*-
"""
netprobe/stats.py
=================
NetProbe — UDP Tabanlı Güvenilir Dosya Aktarım Sistemi
Bursa Teknik Üniversitesi | Bilgisayar Ağları Dersi

Performans analizi modülü.

Aktarım tamamlandıktan sonra ``NetLogger`` nesnesindeki olay kayıtlarını
okuyarak aşağıdaki metrikleri hesaplar ve raporlar:

    Throughput       : Toplam gönderilen byte / tamamlanma süresi  [Bps]
    Goodput          : Gerçek dosya boyutu / tamamlanma süresi     [Bps]
    Packet Loss Rate : Kayıp paket oranı                           [%]
    Retransmit Rate  : Yeniden gönderme oranı                      [%]
    Ortalama RTT     : ACK_RECV olaylarından hesaplanan RTT ortalaması [ms]
    Completion Time  : İlk SEND ile FIN arasındaki süre            [s]

Kullanım:
    >>> from netprobe.logger import NetLogger
    >>> from netprobe.stats  import StatsCalculator
    >>>
    >>> logger = NetLogger()
    >>> # ... aktarım ...
    >>> stats = StatsCalculator(logger)
    >>> stats.print_report(total_bytes_sent=10500, file_size_bytes=10240,
    ...                    total_sent=10, total_lost=1, total_retransmit=2)
"""

from typing import Any, Dict, Optional

from netprobe.logger import EventType, NetLogger


# ---------------------------------------------------------------------------
# Renk Kodları (logger.py ile bağımsız, tekrar tanımlı)
# ---------------------------------------------------------------------------

class _C:
    """Rapor çıktısı için ANSI renk sabitleri."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    BLUE    = "\033[94m"


# ---------------------------------------------------------------------------
# StatsCalculator
# ---------------------------------------------------------------------------

class StatsCalculator:
    """
    NetProbe performans metrikleri hesaplayıcısı.

    Bir ``NetLogger`` nesnesi üzerindeki olay kayıtlarını analiz ederek
    aktarım kalitesini ölçen metrikleri hesaplar ve raporlar.

    Attributes:
        logger (NetLogger): Olay kayıtlarının alınacağı logger nesnesi.

    Örnek:
        >>> logger = NetLogger()
        >>> # aktarım yapılır...
        >>> calc = StatsCalculator(logger)
        >>> print(calc.average_rtt())
        12.345
        >>> calc.print_report(
        ...     total_bytes_sent=10500,
        ...     file_size_bytes=10240,
        ...     total_sent=10,
        ...     total_lost=1,
        ...     total_retransmit=2,
        ... )
    """

    def __init__(self, logger: NetLogger) -> None:
        """
        StatsCalculator'ı başlatır.

        Args:
            logger (NetLogger): Olay kayıtlarını içeren logger nesnesi.
                                Aktarım tamamlandıktan sonra verilmelidir.
        """
        self._logger = logger

    # ------------------------------------------------------------------
    # Bireysel Metrik Hesaplayıcılar
    # ------------------------------------------------------------------

    def throughput(self, total_bytes_sent: int, completion_time_s: float) -> float:
        """
        Ağ verimini (throughput) hesaplar.

        Throughput, protokol başlıkları dahil gönderilen toplam verinin
        tamamlanma süresine oranıdır. Yeniden gönderilen paketler de
        bu değere dahildir, bu yüzden goodput'tan büyük olabilir.

        Formül:
            throughput = total_bytes_sent / completion_time_s  [Bps]

        Args:
            total_bytes_sent  (int)  : Başlık dahil toplam gönderilen byte.
            completion_time_s (float): Aktarımın tamamlanma süresi (saniye).

        Returns:
            float: Throughput değeri (byte/saniye). Süre sıfırsa 0.0 döner.

        Örnek:
            >>> calc.throughput(total_bytes_sent=10500, completion_time_s=2.1)
            5000.0
        """
        if completion_time_s <= 0:
            return 0.0
        return total_bytes_sent / completion_time_s

    def goodput(self, file_size_bytes: int, completion_time_s: float) -> float:
        """
        Gerçek dosya aktarım verimini (goodput) hesaplar.

        Goodput, yeniden gönderimleri ve protokol başlıklarını dışarıda
        bırakarak yalnızca kullanışlı verinin ne hızla iletildiğini ölçer.
        Her zaman throughput'tan küçük veya eşittir.

        Formül:
            goodput = file_size_bytes / completion_time_s  [Bps]

        Args:
            file_size_bytes   (int)  : Gönderilmek istenen dosyanın gerçek boyutu (byte).
            completion_time_s (float): Aktarımın tamamlanma süresi (saniye).

        Returns:
            float: Goodput değeri (byte/saniye). Süre sıfırsa 0.0 döner.
        """
        if completion_time_s <= 0:
            return 0.0
        return file_size_bytes / completion_time_s

    def packet_loss_rate(self, total_sent: int, total_lost: int) -> float:
        """
        Paket kayıp oranını hesaplar.

        Formül:
            loss_rate = (total_lost / total_sent) × 100  [%]

        Args:
            total_sent (int): Gönderilmeye çalışılan toplam paket sayısı
                              (ilk gönderimler; retransmit'ler dahil değil).
            total_lost (int): Kayıp paket sayısı (ACK alınamayan paketler).

        Returns:
            float: Kayıp oranı [0.0 – 100.0]. total_sent sıfırsa 0.0 döner.

        Örnek:
            >>> calc.packet_loss_rate(total_sent=100, total_lost=5)
            5.0
        """
        if total_sent <= 0:
            return 0.0
        return (total_lost / total_sent) * 100.0

    def retransmission_rate(self, total_sent: int, total_retransmit: int) -> float:
        """
        Yeniden gönderme oranını hesaplar.

        Formül:
            retransmit_rate = (total_retransmit / total_sent) × 100  [%]

        Args:
            total_sent       (int): İlk gönderilen paket sayısı.
            total_retransmit (int): Yeniden gönderilen paket sayısı
                                    (logger'daki RETRANSMIT olayı sayısından
                                     da elde edilebilir).

        Returns:
            float: Yeniden gönderme oranı [%]. total_sent sıfırsa 0.0 döner.
        """
        if total_sent <= 0:
            return 0.0
        return (total_retransmit / total_sent) * 100.0

    def average_rtt(self) -> float:
        """
        Ortalama Round-Trip Time (RTT) değerini hesaplar.

        Logger'daki tüm ``ACK_RECV`` olaylarının ``rtt_ms`` alanını okuyarak
        aritmetik ortalama alır.

        Formül:
            avg_rtt = Σ(rtt_ms) / ACK_RECV_sayısı  [ms]

        Returns:
            float: Ortalama RTT (milisaniye). Hiç ACK kaydı yoksa 0.0 döner.

        Örnek:
            >>> calc.average_rtt()
            14.732
        """
        ack_events = self._logger.get_events(EventType.ACK_RECV)
        rtts = [
            e.details["rtt_ms"]
            for e in ack_events
            if "rtt_ms" in e.details
        ]
        if not rtts:
            return 0.0
        return sum(rtts) / len(rtts)

    def min_rtt(self) -> float:
        """
        En düşük RTT değerini döndürür.

        Returns:
            float: Minimum RTT (ms). Kayıt yoksa 0.0 döner.
        """
        ack_events = self._logger.get_events(EventType.ACK_RECV)
        rtts = [e.details["rtt_ms"] for e in ack_events if "rtt_ms" in e.details]
        return min(rtts, default=0.0)

    def max_rtt(self) -> float:
        """
        En yüksek RTT değerini döndürür.

        Returns:
            float: Maksimum RTT (ms). Kayıt yoksa 0.0 döner.
        """
        ack_events = self._logger.get_events(EventType.ACK_RECV)
        rtts = [e.details["rtt_ms"] for e in ack_events if "rtt_ms" in e.details]
        return max(rtts, default=0.0)

    def completion_time(self) -> float:
        """
        Aktarımın toplam tamamlanma süresini hesaplar.

        İlk ``SEND`` olayının zaman damgasıyla ``FIN`` olayının zaman damgası
        arasındaki farkı döndürür. Eğer logger'dan hesaplanamıyorsa
        FIN olayındaki ``total_time_s`` detay alanına başvurur.

        Formül:
            completion_time = t(FIN) − t(ilk SEND)  [s]

        Returns:
            float: Tamamlanma süresi (saniye). Hesaplanamıyorsa 0.0 döner.

        Örnek:
            >>> calc.completion_time()
            3.742
        """
        send_events = self._logger.get_events(EventType.SEND)
        fin_events  = self._logger.get_events(EventType.FIN)

        if send_events and fin_events:
            t_start = send_events[0].timestamp
            t_end   = fin_events[-1].timestamp
            return max(t_end - t_start, 0.0)

        # Alternatif: FIN olayındaki total_time_s alanından al
        if fin_events and "total_time_s" in fin_events[-1].details:
            return fin_events[-1].details["total_time_s"]

        return 0.0

    def timeout_count(self) -> int:
        """
        Gerçekleşen toplam timeout sayısını döndürür.

        Returns:
            int: Logger'daki TIMEOUT olay sayısı.
        """
        return len(self._logger.get_events(EventType.TIMEOUT))

    def retransmit_count(self) -> int:
        """
        Gerçekleşen toplam yeniden gönderme sayısını logger'dan okur.

        Returns:
            int: Logger'daki RETRANSMIT olay sayısı.
        """
        return len(self._logger.get_events(EventType.RETRANSMIT))

    def drop_count(self) -> int:
        """
        Simülatör tarafından düşürülen paket sayısını döndürür.

        Returns:
            int: Logger'daki DROP olay sayısı.
        """
        return len(self._logger.get_events(EventType.DROP))

    def error_count(self) -> int:
        """
        Checksum veya protokol hatası sayısını döndürür.

        Returns:
            int: Logger'daki ERROR olay sayısı.
        """
        return len(self._logger.get_events(EventType.ERROR))

    # ------------------------------------------------------------------
    # Özet
    # ------------------------------------------------------------------

    def summary(
        self,
        total_bytes_sent: int,
        file_size_bytes: int,
        total_sent: int,
        total_lost: int,
        total_retransmit: Optional[int] = None,
        completion_time_s: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Tüm metrikleri hesaplayarak tek bir sözlükte döndürür.

        Bu sözlük hem ``print_report()`` hem de dışa aktarma
        (JSON rapor dosyası) için kullanılır.

        Args:
            total_bytes_sent   (int)           : Başlık dahil toplam gönderilen byte.
            file_size_bytes    (int)           : Gerçek dosya boyutu (byte).
            total_sent         (int)           : İlk gönderilen paket sayısı.
            total_lost         (int)           : Kayıp paket sayısı.
            total_retransmit   (int | None)    : Yeniden gönderilen paket sayısı.
                                                 None verilirse logger'dan okunur.
            completion_time_s  (float | None)  : Dışarıdan verilen tamamlanma süresi.
                                                 None verilirse logger'dan hesaplanır.

        Returns:
            dict: Aşağıdaki anahtarları içeren performans metrikleri sözlüğü:
                  completion_time_s, throughput_bps, goodput_bps,
                  packet_loss_pct, retransmission_pct,
                  avg_rtt_ms, min_rtt_ms, max_rtt_ms,
                  timeout_count, retransmit_count, drop_count, error_count,
                  total_bytes_sent, file_size_bytes, total_sent, total_lost.
        """
        if completion_time_s is None:
            completion_time_s = self.completion_time()

        if total_retransmit is None:
            total_retransmit = self.retransmit_count()

        # completion_time_s <= 0 ise logger'dan yeniden hesapla
        # (Windows'ta cok hizli transferlerde time.monotonic() 0 donebilir)
        if completion_time_s <= 0:
            completion_time_s = self.completion_time()
        # Hala 0 ise toplam_bytes_sent'ten minumum bir deger tahmin et
        # (saniyede en az 1 MB/s varsayarak)
        if completion_time_s <= 0 and total_bytes_sent > 0:
            completion_time_s = total_bytes_sent / 1_000_000_000.0  # 1 GB/s alt sinir

        return {
            # Süre
            "completion_time_s":  round(completion_time_s, 6),
            # Bant genişliği metrikleri
            "throughput_bps":     round(self.throughput(total_bytes_sent, completion_time_s), 2),
            "goodput_bps":        round(self.goodput(file_size_bytes, completion_time_s), 2),
            # Kayıp / yeniden gönderim oranları
            "packet_loss_pct":    round(self.packet_loss_rate(total_sent, total_lost), 4),
            "retransmission_pct": round(self.retransmission_rate(total_sent, total_retransmit), 4),
            # RTT istatistikleri
            "avg_rtt_ms":         round(self.average_rtt(), 3),
            "min_rtt_ms":         round(self.min_rtt(), 3),
            "max_rtt_ms":         round(self.max_rtt(), 3),
            # Sayaçlar (logger'dan)
            "timeout_count":      self.timeout_count(),
            "retransmit_count":   self.retransmit_count(),
            "drop_count":         self.drop_count(),
            "error_count":        self.error_count(),
            # Ham veriler
            "total_bytes_sent":   total_bytes_sent,
            "file_size_bytes":    file_size_bytes,
            "total_sent":         total_sent,
            "total_lost":         total_lost,
        }

    # ------------------------------------------------------------------
    # Rapor Yazdırma
    # ------------------------------------------------------------------

    def print_report(
        self,
        total_bytes_sent: int,
        file_size_bytes: int,
        total_sent: int,
        total_lost: int,
        total_retransmit: Optional[int] = None,
        completion_time_s: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Performans özetini güzel formatlı olarak ekrana basar.

        ``summary()`` metodunu çağırır, ardından sonuçları renkli ve
        hizalı bir tablo biçiminde konsola yazar.

        Args:
            total_bytes_sent   (int)          : Başlık dahil toplam gönderilen byte.
            file_size_bytes    (int)           : Gerçek dosya boyutu (byte).
            total_sent         (int)           : İlk gönderilen paket sayısı.
            total_lost         (int)           : Kayıp paket sayısı.
            total_retransmit   (int | None)    : Yeniden gönderilen paket sayısı.
            completion_time_s  (float | None)  : Tamamlanma süresi; None → logger'dan.

        Returns:
            dict: ``summary()`` döndüren metriklerin tamamı (dışa aktarım için).

        Örnek:
            >>> calc.print_report(
            ...     total_bytes_sent=10500,
            ...     file_size_bytes=10240,
            ...     total_sent=10,
            ...     total_lost=1,
            ...     total_retransmit=2,
            ... )
        """
        m = self.summary(
            total_bytes_sent=total_bytes_sent,
            file_size_bytes=file_size_bytes,
            total_sent=total_sent,
            total_lost=total_lost,
            total_retransmit=total_retransmit,
            completion_time_s=completion_time_s,
        )

        # ── Yardımcı formatlayıcılar ─────────────────────────────────
        def _bps(val: float) -> str:
            """Bps → insan okunabilir birim (Bps, KBps, MBps)."""
            if val >= 1_000_000:
                return f"{val / 1_000_000:.2f} MB/s"
            if val >= 1_000:
                return f"{val / 1_000:.2f} KB/s"
            return f"{val:.2f} B/s"

        def _bytes(val: int) -> str:
            """Byte → insan okunabilir birim."""
            if val >= 1_048_576:
                return f"{val / 1_048_576:.2f} MB ({val:,} byte)"
            if val >= 1_024:
                return f"{val / 1_024:.2f} KB ({val:,} byte)"
            return f"{val:,} byte"

        def _row(label: str, value: str, color: str = _C.WHITE) -> None:
            print(f"  {_C.BOLD}{label:<28}{_C.RESET}  {color}{value}{_C.RESET}")

        def _section(title: str) -> None:
            print(f"\n  {_C.BOLD}{_C.BLUE}>> {title}{_C.RESET}")
            print(f"  {'=' * 50}")

        # ── Rapor başlığı ─────────────────────────────────────────────
        border = "=" * 56
        print(f"\n{_C.BOLD}{_C.MAGENTA}{'=' * 56}{_C.RESET}")
        print(f"{_C.BOLD}{_C.MAGENTA}  NetProbe -- Aktarim Performans Raporu{_C.RESET}")
        print(f"{_C.BOLD}{_C.MAGENTA}{border}{_C.RESET}")

        # ── Süre ──────────────────────────────────────────────────────
        _section("Süre")
        _row("Tamamlanma Süresi",
             f"{m['completion_time_s']:.4f} s",
             _C.CYAN)

        # ── Bant Genişliği ────────────────────────────────────────────
        _section("Bant Genişliği")
        _row("Throughput",
             f"{_bps(m['throughput_bps'])}",
             _C.GREEN)
        _row("Goodput",
             f"{_bps(m['goodput_bps'])}",
             _C.GREEN)
        _row("Gönderilen Veri",
             _bytes(m["total_bytes_sent"]),
             _C.WHITE)
        _row("Dosya Boyutu",
             _bytes(m["file_size_bytes"]),
             _C.WHITE)

        # ── Güvenilirlik ──────────────────────────────────────────────
        _section("Güvenilirlik")

        loss_color  = _C.RED    if m["packet_loss_pct"]    > 5  else _C.GREEN
        retr_color  = _C.YELLOW if m["retransmission_pct"] > 0  else _C.GREEN

        _row("Paket Kayıp Oranı",
             f"{m['packet_loss_pct']:.2f}%  ({m['total_lost']}/{m['total_sent']} paket)",
             loss_color)
        _row("Yeniden Gönderim Oranı",
             f"{m['retransmission_pct']:.2f}%  ({m['retransmit_count']} retransmit)",
             retr_color)
        _row("Timeout Sayısı",
             str(m["timeout_count"]),
             _C.YELLOW if m["timeout_count"] > 0 else _C.GREEN)
        _row("DROP Sayısı (sim.)",
             str(m["drop_count"]),
             _C.RED if m["drop_count"] > 0 else _C.GREEN)
        _row("Hata Sayısı",
             str(m["error_count"]),
             _C.RED if m["error_count"] > 0 else _C.GREEN)

        # ── RTT ───────────────────────────────────────────────────────
        _section("Round-Trip Time (RTT)")
        _row("Ortalama RTT", f"{m['avg_rtt_ms']:.3f} ms", _C.CYAN)
        _row("Min RTT",      f"{m['min_rtt_ms']:.3f} ms", _C.CYAN)
        _row("Max RTT",      f"{m['max_rtt_ms']:.3f} ms", _C.CYAN)

        # ── Sonuç ─────────────────────────────────────────────────────
        print(f"\n{_C.BOLD}{_C.MAGENTA}{border}{_C.RESET}\n")

        return m

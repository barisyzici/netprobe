# -*- coding: utf-8 -*-
"""
simulator/network_emulator.py
==============================
NetProbe -- UDP Tabanli Guvenilir Dosya Aktarim Sistemi
Bursa Teknik Universitesi | Bilgisayar Aglari Dersi

Ag kosulu simülatörü.

Gercek bir UDP soketi üzerine sarmalayici (wrapper) uygulayarak:
  - Belirli olasilikla paket kaybini (loss) taklit eder
  - Her gönderime yapay gecikme (delay) ekler

Kayip sadece gönderim (sendto) tarafinda uygulanir.
Bu, tek tarafli paket düsürmeyi simüle eder ve protokolün
yeniden gönderim mekanizmasini test etmeyi saglar.

Kullanim:
    from simulator.network_emulator import NetworkEmulator

    emulator = NetworkEmulator(loss_prob=0.1, delay_ms=50, logger=logger)
    sock = emulator.wrap_socket(real_sock)

    # Artik sock.sendto() / sock.recvfrom() emüle edilmis davranir
    sock.sendto(data, addr)   # %10 olasilikla düsürülür + 50ms gecikme
    data, addr = sock.recvfrom(65535)  # dogrudan gecis
"""

import random
import socket
import time
from typing import Any, Optional, Tuple

from netprobe.logger import NetLogger
from netprobe.packet import identify_packet


# ---------------------------------------------------------------------------
# NetworkEmulator
# ---------------------------------------------------------------------------

class NetworkEmulator:
    """
    Ag kaybini ve gecikmesini taklit eden simülatör.

    Gercek bir UDP soketi uzerine ``EmulatedSocket`` sarmalayi uygular.
    Sarmalayici, ``sendto()`` cagrilarinda kayip ve gecikme uygular;
    ``recvfrom()`` cagrilari degistirilmeksizin gercek sokete iletilir.

    Attributes:
        loss_prob (float)          : Paket kayip olasiligi [0.0 - 1.0].
        delay_ms  (int)            : Her gönderime eklenen gecikme (ms).
        logger    (NetLogger|None) : Düsürülen paketleri loglayan nesne.

    Ornek:
        >>> em = NetworkEmulator(loss_prob=0.1, delay_ms=20)
        >>> wrapped = em.wrap_socket(sock)
        >>> wrapped.sendto(data, addr)  # %10 olasilikla düsürülür
    """

    def __init__(
        self,
        loss_prob: float = 0.0,
        delay_ms:  int   = 0,
        logger:    Optional[NetLogger] = None,
    ) -> None:
        """
        NetworkEmulator'i baslatir ve parametrelerini dogrular.

        Args:
            loss_prob (float)         : Paket kayip olasiligi [0.0 - 1.0].
                                        0.0 = kayip yok, 1.0 = tümü düsürülür.
            delay_ms  (int)           : Her gönderime eklenen gecikme (ms, >= 0).
            logger    (NetLogger|None): Kayip olaylarini kaydetmek icin logger.
                                        None ise olaylar kaydedilmez.

        Raises:
            ValueError: loss_prob [0,1] araliginda degilse veya delay_ms < 0 ise.
        """
        if not (0.0 <= loss_prob <= 1.0):
            raise ValueError(
                f"loss_prob [0.0, 1.0] araliginda olmalidir: {loss_prob}"
            )
        if delay_ms < 0:
            raise ValueError(f"delay_ms negatif olamaz: {delay_ms}")

        self.loss_prob = loss_prob
        self.delay_ms  = delay_ms
        self.logger    = logger

        # Istatistik sayaclari
        self._total_sent    = 0
        self._total_dropped = 0

    # ------------------------------------------------------------------
    # Karar Fonksiyonlari
    # ------------------------------------------------------------------

    def should_drop(self) -> bool:
        """
        Geçerli paketi düsürüp düsürmeme kararini verir.

        Düzgün dagilimli bir rastgele sayi ``loss_prob`` ile karsilastirilir.
        Bu, her cagri bagimsiz bir Bernoulli deneyi olusturur.

        Returns:
            bool: True ise paket düsürülmeli, False ise gönderilmeli.

        Ornek:
            >>> em = NetworkEmulator(loss_prob=0.3)
            >>> # Uzun vadede yaklasik %30 True döner
            >>> em.should_drop()
            False
        """
        return random.random() < self.loss_prob

    def apply_delay(self) -> None:
        """
        Yapilandirilmis gecikmeyi uygular (bloklayici).

        ``delay_ms`` > 0 ise ``time.sleep()`` ile beklenir.
        delay_ms = 0 ise gecikme uygulanmaz (no-op).
        """
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)

    # ------------------------------------------------------------------
    # Soket Sarmalama
    # ------------------------------------------------------------------

    def wrap_socket(self, sock: socket.socket) -> "EmulatedSocket":
        """
        Gercek UDP soketini ``EmulatedSocket`` ile sarlar.

        Döndürülen nesne, gercek soketle ayni ``sendto()`` / ``recvfrom()``
        arayüzünü sunar; ek olarak kayip ve gecikme emülasyonu uygular.

        Args:
            sock (socket.socket): Sarmalanacak gercek UDP soketi.

        Returns:
            EmulatedSocket: Emüle edilmis soket nesnesi.

        Ornek:
            >>> wrapped = emulator.wrap_socket(real_sock)
            >>> wrapped.sendto(data, (ip, port))  # emüle edilmis
        """
        return EmulatedSocket(sock, self)

    # ------------------------------------------------------------------
    # Istatistikler
    # ------------------------------------------------------------------

    @property
    def drop_rate(self) -> float:
        """
        Gercek paket kayip oranini döndürür (gözlemlenen).

        Returns:
            float: Gerçek kayıp oranı [0.0 - 1.0]. Hic gönderim yoksa 0.0.
        """
        if self._total_sent == 0:
            return 0.0
        return self._total_dropped / self._total_sent

    def stats(self) -> dict:
        """
        Simülatör calisma istatistiklerini döndürür.

        Returns:
            dict: total_sent, total_dropped, drop_rate, loss_prob, delay_ms.
        """
        return {
            "total_sent":    self._total_sent,
            "total_dropped": self._total_dropped,
            "drop_rate":     round(self.drop_rate, 4),
            "loss_prob":     self.loss_prob,
            "delay_ms":      self.delay_ms,
        }


# ---------------------------------------------------------------------------
# EmulatedSocket
# ---------------------------------------------------------------------------

class EmulatedSocket:
    """
    Gercek UDP soketini sarmalayan, emüle edilmis soket nesnesi.

    Gercek soketle ayni arayüzü (sendto, recvfrom, bind, close vb.) saglar.
    ``sendto()`` cagrilarinda kayip ve gecikme emülasyonu uygulanir.
    Diger metodlar dogrudan gercek sokete yönlendirilir.

    Attributes:
        _sock     (socket.socket)  : Sarmalanan gercek UDP soketi.
        _emulator (NetworkEmulator): Kayip/gecikme kararlarini veren emülatör.
    """

    def __init__(
        self,
        sock:     socket.socket,
        emulator: NetworkEmulator,
    ) -> None:
        """
        EmulatedSocket'i baslatir.

        Args:
            sock     (socket.socket)  : Sarmalanacak gercek UDP soketi.
            emulator (NetworkEmulator): Emülasyon mantigi saglayici.
        """
        self._sock     = sock
        self._emulator = emulator

    # ------------------------------------------------------------------
    # Emüle Edilmis sendto
    # ------------------------------------------------------------------

    def sendto(self, data: bytes, addr: Tuple[str, int]) -> int:
        """
        Emüle edilmis paket gönderimi.

        Akis:
            1. should_drop() ile kayip karari verilir.
            2. Kayip: logger.log_drop() cagrilir, veri sessizce atilir.
            3. Gönderim: apply_delay() ile gecikme uygulanir,
               ardindan gercek sock.sendto() cagrilir.

        Args:
            data (bytes)          : Gönderilecek ham UDP verisi.
            addr (Tuple[str, int]): Hedef (IP, port) adresi.

        Returns:
            int: Gönderilen byte sayisi (kayip durumunda len(data) sahte deger).
        """
        self._emulator._total_sent += 1

        if self._emulator.should_drop():
            # ── Paket düsürüldü ──────────────────────────────────────
            self._emulator._total_dropped += 1

            if self._emulator.logger is not None:
                # Seq numarasini ham veriden cözümlemeye calis
                seq_num = -1
                try:
                    name, _ = identify_packet(data)
                    if name in ("DATA", "FIN"):
                        # DataPacket header'inda SEQ_NUM 1..5. byte araliginda
                        import struct
                        _, seq_num = struct.unpack_from("!BI", data, 0)
                except Exception:
                    pass
                self._emulator.logger.log_drop(seq_num)

            # Sessizce geri dön (gerçekte hicbir sey gönderilmedi)
            return len(data)

        # ── Gecikme + gercek gönderim ────────────────────────────────
        self._emulator.apply_delay()
        return self._sock.sendto(data, addr)

    # ------------------------------------------------------------------
    # Dogrudan Gecis: recvfrom
    # ------------------------------------------------------------------

    def recvfrom(self, bufsize: int) -> Tuple[bytes, Tuple[str, int]]:
        """
        Paketi dogrudan gercek soket üzerinden alir.

        Kayip sadece gönderim tarafinda simüle edilir; alim tarafinda
        herhangi bir degisiklik yapilmaz.

        Args:
            bufsize (int): Okunacak maksimum byte sayisi.

        Returns:
            Tuple[bytes, Tuple[str,int]]: (veri, (IP, port)) demeti.
        """
        return self._sock.recvfrom(bufsize)

    # ------------------------------------------------------------------
    # Diger Soket Metodlari (delegasyon)
    # ------------------------------------------------------------------

    def bind(self, addr: Tuple[str, int]) -> None:
        """Gercek soketi belirtilen adrese baglar."""
        self._sock.bind(addr)

    def close(self) -> None:
        """Gercek soketi kapatir."""
        self._sock.close()

    def setsockopt(self, *args: Any, **kwargs: Any) -> None:
        """Soket seçeneklerini gercek soket üzerinde ayarlar."""
        self._sock.setsockopt(*args, **kwargs)

    def getsockname(self) -> Tuple[str, int]:
        """Sokete bagli yerel adresi döndürür."""
        return self._sock.getsockname()

    def fileno(self) -> int:
        """
        Sokete ait dosya tanimlayicisini döndürür.

        select.select() cagrilarinin EmulatedSocket üzerinde calisabilmesi
        icin zorunludur; select, nesneyi fileno() üzerinden tanimlar.

        Returns:
            int: Gercek soketin dosya tanimlayicisi (fd).
        """
        return self._sock.fileno()

    def __repr__(self) -> str:
        return (
            f"EmulatedSocket(loss={self._emulator.loss_prob:.0%}, "
            f"delay={self._emulator.delay_ms}ms, "
            f"dropped={self._emulator._total_dropped}/"
            f"{self._emulator._total_sent})"
        )

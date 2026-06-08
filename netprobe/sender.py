# -*- coding: utf-8 -*-
"""
netprobe/sender.py
==================
NetProbe -- UDP Tabanli Guvenilir Dosya Aktarim Sistemi
Bursa Teknik Universitesi | Bilgisayar Aglari Dersi

Gönderici taraf implementasyonu.

Sender sinifi UDP soketi üzerinden dosyayi güvenilir olarak gönderir.
ProtocolConfig'de belirlenen moda göre (SAW veya GBN) farkli algoritmalar
kullanilir.

select.select() kullanimi:
    sock.settimeout() yerine select.select() tercih edilir cünkü:
    - Platform bagimliligini azaltir (Windows'ta da stabil calisir)
    - Non-blocking okuma ile polling araligini kontrol etmeyi saglar
    - GBN modunda kisa polling + timeout kontrolü kombine edilebilir

Aktarim akisi:
    1. split_file() ile dosya chunk'lara bölünür
    2. Moda göre _send_saw() veya _send_gbn() cagrilir
    3. Teardown: FIN gönderilir, FIN-ACK beklenir
    4. logger.log_fin() ile tamamlanma kaydedilir
    5. send_file() istatistik sözlügü döndürür
"""

import os
import select
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

import config
from netprobe.logger import NetLogger
from netprobe.packet import (
    AckPacket,
    DataPacket,
    STATUS_NAK,
    TYPE_ACK,
    TYPE_FIN_ACK,
    make_fin_packet,
    identify_packet,
)
from netprobe.protocol import ProtocolConfig, ProtocolMode, split_file


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------

class Sender:
    """
    UDP üzerinden guvenilir dosya gönderme motoru.

    Bir ``ProtocolConfig`` nesnesindeki moda göre Stop-and-Wait veya
    Go-Back-N algoritmalarini kullanir.

    Attributes:
        _sock        (socket.socket)  : Kullanilan UDP soketi.
        _server_addr (Tuple[str,int]) : (IP, port) gönderilecek hedef.
        _logger      (NetLogger)      : Olay kayitlari icin logger.
        _cfg         (ProtocolConfig) : Protokol konfigürasyonu.

    Ornek:
        >>> import socket
        >>> sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        >>> logger = NetLogger()
        >>> cfg = ProtocolConfig()
        >>> sender = Sender(sock, ("127.0.0.1", 9000), logger, cfg)
        >>> stats = sender.send_file("gonder.bin")
        >>> logger.close()
    """

    def __init__(
        self,
        sock: socket.socket,
        server_addr: Tuple[str, int],
        logger: NetLogger,
        cfg: ProtocolConfig,
    ) -> None:
        """
        Sender'i baslatir.

        Args:
            sock        (socket.socket) : Non-blocking olmayan UDP soketi.
            server_addr (tuple)         : Hedef sunucu (IP, port).
            logger      (NetLogger)     : Olay kayit sistemi.
            cfg         (ProtocolConfig): Protokol konfigürasyonu.
        """
        self._sock        = sock
        self._server_addr = server_addr
        self._logger      = logger
        self._cfg         = cfg

    # ------------------------------------------------------------------
    # Ana Metod
    # ------------------------------------------------------------------

    def send_file(self, filepath: str) -> Dict[str, Any]:
        """
        Belirtilen dosyayi sunucuya gönderir.

        Dosyayi chunk'lara böler, moda göre SAW veya GBN algoritmini
        secer ve teardown islemini tamamlar. Bitis istatistiklerini döndürür.

        Args:
            filepath (str): Gönderilecek dosyanin tam yolu.

        Returns:
            Dict[str, Any]: Aktarim istatistikleri:
                - ``file_size_bytes``  : Dosyanin gercek boyutu (byte)
                - ``total_chunks``     : Toplam paket sayisi
                - ``total_bytes_sent`` : Baslík dahil gönderilen toplam byte
                - ``total_sent``       : Ilk gönderim sayisi (retransmit hariç)
                - ``total_lost``       : Basarisiz olan paket sayisi
                - ``completion_time_s``: Toplam süre (saniye)

        Raises:
            FileNotFoundError: Dosya bulunamazsa.
            RuntimeError     : Teardown (FIN-ACK) alinamazsa.
        """
        file_size = os.path.getsize(filepath)
        chunks = split_file(filepath, self._cfg.chunk_size)
        total = len(chunks)

        t_start = time.perf_counter()

        # Moda göre gönderim yap
        if self._cfg.mode == ProtocolMode.SAW:
            stats = self._send_saw(chunks)
        else:
            # GBN ve SR icin GBN kullan (SR ileriki surum)
            stats = self._send_gbn(chunks)

        # Teardown: FIN + FIN-ACK
        fin_ok = self._send_teardown(total_packets=total)
        if not fin_ok:
            self._logger.log_error(-1, "FIN-ACK", "max_retries_exceeded")

        completion_time = time.perf_counter() - t_start
        # Windows'ta cok hizli loopback transferlerde 0 gelebilir;
        # minimum 1 mikrosaniye kullan
        if completion_time <= 0:
            completion_time = 1e-6
        self._logger.log_fin(completion_time)

        # Ek meta bilgi
        stats["file_size_bytes"]   = file_size
        stats["total_chunks"]      = total
        stats["completion_time_s"] = round(completion_time, 6)

        return stats

    # ------------------------------------------------------------------
    # Stop-and-Wait
    # ------------------------------------------------------------------

    def _send_saw(self, chunks: List[Tuple[int, bytes]]) -> Dict[str, Any]:
        """
        Stop-and-Wait (SAW) aktarim algoritmini uygular.

        Her paket gönderildikten sonra ACK beklenir. ACK belirtilen süre
        (TIMEOUT_SEC) icinde gelmezse paket yeniden gönderilir. MAX_RETRIES
        denemesinin tamami bosscikmadan ACK alinamazsa paket kayip olarak
        isaret edilir ve bir sonrakine gecilir.

        Algoritma:
            for her chunk:
                deneme = 0
                while deneme < max_retries:
                    paketi gönder
                    select ile ACK bekle (timeout_sec)
                    ACK geldi ve dogruysa: sonraki pakete gec
                    Timeout: deneme++, log_timeout, log_retransmit
                deneme doldu: log_error, kayip sayacini artir

        Args:
            chunks (List[Tuple[int,bytes]]): split_file() ciktisi.

        Returns:
            Dict[str, Any]: total_bytes_sent, total_sent, total_lost.
        """
        total           = len(chunks)
        total_bytes_sent = 0
        total_lost       = 0
        total_sent       = 0  # ilk gönderimler

        for seq_num, payload in chunks:
            pkt = DataPacket(
                seq_num=seq_num,
                total_packets=total,
                payload=payload,
            )
            raw_pkt = pkt.to_bytes()
            pkt_size = len(raw_pkt)
            acked = False

            for attempt in range(1, self._cfg.max_retries + 1):
                # Gönder
                try:
                    self._sock.sendto(raw_pkt, self._server_addr)
                except OSError as exc:
                    self._logger.log_error(seq_num, "socket_send", str(exc))
                    break

                total_bytes_sent += pkt_size
                if attempt == 1:
                    total_sent += 1
                    self._logger.log_send(seq_num, pkt_size)
                else:
                    self._logger.log_retransmit(seq_num, attempt - 1)

                t_send = time.monotonic()

                # ACK bekle (select ile)
                readable, _, _ = select.select(
                    [self._sock], [], [], self._cfg.timeout_sec
                )

                if not readable:
                    # Timeout
                    self._logger.log_timeout(seq_num, attempt)
                    continue

                # Yaniti oku
                try:
                    raw_ack, addr = self._sock.recvfrom(config.SOCKET_BUFFER_SIZE)
                    ack = AckPacket.from_bytes(raw_ack)
                except (ValueError, OSError) as exc:
                    # Bozuk paket — yeniden dene
                    self._logger.log_error(seq_num, "valid_ack", str(exc))
                    continue

                rtt_ms = (time.monotonic() - t_send) * 1000.0

                # Dogru ACK mi?
                if ack.ack_num == seq_num and not ack.is_nak:
                    self._logger.log_ack(seq_num, rtt_ms)
                    acked = True
                    break
                # Duplicate / eski ACK: yok say, dongu tekrar deneyecek
                # (attempt sayacini artirmadan devam et)

            if not acked:
                total_lost += 1
                self._logger.log_error(
                    seq_num, "ack_received", "max_retries_exceeded"
                )

        return {
            "total_bytes_sent": total_bytes_sent,
            "total_sent":       total_sent,
            "total_lost":       total_lost,
        }

    # ------------------------------------------------------------------
    # Go-Back-N
    # ------------------------------------------------------------------

    def _send_gbn(self, chunks: List[Tuple[int, bytes]]) -> Dict[str, Any]:
        """
        Go-Back-N (GBN) sliding window aktarim algoritmini uygular.

        WINDOW_SIZE kadar paket ayni anda ucusta olabilir. Her paketin
        kendi zamanlayicisi ``send_times`` sözlügünde tutulur.
        Penceredeki en eski paketin süresi dolunca tüm pencere yeniden
        gönderilir (GBN semantigi).

        Algoritma:
            base = 0           # onaylanmamis en eski paket
            next_seq = 0       # gönderilecek sonraki paket

            döngü (base < total):
                pencere dolana kadar paketleri gönder
                select ile kisa süre ACK bekle (10ms polling)
                ACK alindiysa:
                    NAK  -> NAK'taki seq'den itibaren yeniden gönder
                    ACK  -> cumulative: base'i ilerlet, RTT hesapla
                Timeout kontrolü (base paket):
                    Penceredeki tüm paketleri yeniden gönder
                    retry_counts[base] asildiysa log_error + base ilerlet

        Args:
            chunks (List[Tuple[int,bytes]]): split_file() ciktisi.

        Returns:
            Dict[str, Any]: total_bytes_sent, total_sent, total_lost.
        """
        total            = len(chunks)
        base             = 0        # onaylanmamis en küçük seq
        next_seq         = 0        # sirada gönderilecek seq
        total_bytes_sent = 0
        total_sent       = 0        # ilk gönderim sayisi
        total_lost       = 0

        # Paket basi zamanlayici: {seq -> float (monotonic)}
        send_times:    Dict[int, float] = {}
        # Paket basi yeniden gönderim sayaci: {seq -> int}
        retry_counts:  Dict[int, int]   = {}

        # GBN polling araligi: timeout'un en fazla 1/20'si (min 5ms)
        poll_interval = max(self._cfg.timeout_sec / 20.0, 0.005)

        while base < total:
            # ── 1. Pencereyi doldur ──────────────────────────────────
            while (
                next_seq < base + self._cfg.window_size
                and next_seq < total
            ):
                seq_num, payload = chunks[next_seq]
                pkt = DataPacket(
                    seq_num=seq_num,
                    total_packets=total,
                    payload=payload,
                )
                raw_pkt = pkt.to_bytes()

                try:
                    self._sock.sendto(raw_pkt, self._server_addr)
                except OSError as exc:
                    self._logger.log_error(seq_num, "socket_send", str(exc))
                    next_seq += 1
                    continue

                pkt_size          = len(raw_pkt)
                total_bytes_sent += pkt_size
                send_times[next_seq]  = time.monotonic()

                if next_seq not in retry_counts:
                    # Ilk gönderim
                    retry_counts[next_seq] = 0
                    total_sent += 1
                    self._logger.log_send(seq_num, pkt_size)
                else:
                    # Yeniden gönderim (pencere geriye alindi)
                    self._logger.log_retransmit(seq_num, retry_counts[next_seq])

                next_seq += 1

            # ── 2. Kisa polling: ACK var mi? ─────────────────────────
            readable, _, _ = select.select(
                [self._sock], [], [], poll_interval
            )

            if readable:
                try:
                    raw_ack, _addr = self._sock.recvfrom(config.SOCKET_BUFFER_SIZE)
                    ack = AckPacket.from_bytes(raw_ack)
                except (ValueError, OSError) as exc:
                    # Bozuk ACK paketi: yok say
                    self._logger.log_error(base, "valid_ack", str(exc))
                    ack = None  # type: ignore[assignment]

                if ack is not None:
                    if ack.is_nak:
                        # ── NAK: NAK'taki seq'den itibaren tekrar gönder
                        nak_seq = ack.ack_num
                        if base <= nak_seq < next_seq:
                            # Pencereyi geri al
                            for s in range(nak_seq, next_seq):
                                retry_counts[s] = retry_counts.get(s, 0) + 1
                                if s in send_times:
                                    del send_times[s]
                            self._logger.log_timeout(nak_seq, retry_counts[nak_seq])
                            next_seq = nak_seq   # pencere geri alindi

                    elif ack.ack_num >= base:
                        # ── Cumulative ACK: base..ack_num arasi tümünü onayla
                        for s in range(base, ack.ack_num + 1):
                            if s in send_times:
                                rtt_ms = (time.monotonic() - send_times[s]) * 1000.0
                                self._logger.log_ack(s, rtt_ms)
                                del send_times[s]
                        base = ack.ack_num + 1

            # ── 3. Timeout kontrolü: en eski paketin süresi doldu mu? ──
            if base in send_times:
                elapsed = time.monotonic() - send_times[base]
                if elapsed > self._cfg.timeout_sec:
                    retry_counts[base] = retry_counts.get(base, 0) + 1

                    if retry_counts[base] > self._cfg.max_retries:
                        # Bu paketi kayip say, base'i ilerlet
                        self._logger.log_error(
                            base, "ack_received", "max_retries_exceeded"
                        )
                        del send_times[base]
                        base += 1
                        total_lost += 1
                    else:
                        # Tüm pencereyi geri al ve yeniden gönder
                        self._logger.log_timeout(base, retry_counts[base])
                        # Penceredeki tüm paketlerin zamanlayicilarini sifirla
                        for s in range(base, next_seq):
                            if s in send_times:
                                del send_times[s]
                        # next_seq'i base'e geri al; bir sonraki döngüde tekrar gönderilir
                        next_seq = base

        return {
            "total_bytes_sent": total_bytes_sent,
            "total_sent":       total_sent,
            "total_lost":       total_lost,
        }

    # ------------------------------------------------------------------
    # Teardown: FIN + FIN-ACK
    # ------------------------------------------------------------------

    def _send_teardown(self, total_packets: int) -> bool:
        """
        Aktarimi sonlandirmak icin FIN paketi gönderir ve FIN-ACK bekler.

        FIN paketi her denemede yeniden gönderilir; MAX_RETRIES denemeden
        sonra FIN-ACK alinamazsa False döner.

        Args:
            total_packets (int): Aktarimdaki toplam paket sayisi (FIN seq'i icin).

        Returns:
            bool: FIN-ACK basariyla alindiysa True, alinamazsa False.
        """
        fin_pkt = make_fin_packet(
            seq_num=total_packets,
            total_packets=total_packets,
        )
        raw_fin = fin_pkt.to_bytes()

        for attempt in range(1, self._cfg.max_retries + 1):
            try:
                self._sock.sendto(raw_fin, self._server_addr)
            except OSError as exc:
                self._logger.log_error(-1, "FIN_send", str(exc))
                return False

            readable, _, _ = select.select(
                [self._sock], [], [], self._cfg.timeout_sec
            )

            if not readable:
                self._logger.log_timeout(-1, attempt)
                continue

            try:
                raw_ack, _ = self._sock.recvfrom(config.SOCKET_BUFFER_SIZE)
                ack = AckPacket.from_bytes(raw_ack)
                if ack.is_fin_ack:
                    return True
            except (ValueError, OSError) as exc:
                self._logger.log_error(-1, "FIN_ACK", str(exc))

        return False

# -*- coding: utf-8 -*-
"""
netprobe/receiver.py
====================
NetProbe -- UDP Tabanli Guvenilir Dosya Aktarim Sistemi
Bursa Teknik Universitesi | Bilgisayar Aglari Dersi

Alici taraf implementasyonu.

Receiver sinifi UDP soketi üzerinden paket alir, ACK/NAK gönderir ve
dolu dosyayi diske yazar. ProtocolConfig'deki moda göre (SAW veya GBN)
farkli kabul stratejileri kullanilir.

SAW Modu:
    Siradaki paketi bekler. Dogru gelirse ACK gönderir, diske yazar.
    Eski/duplikat paket gelirse tekrar ACK gönderir (kaydetmeden).

GBN Modu:
    Sadece beklenen seq_num'u kabul eder (in-order).
    Beklenen disindaki paket gelirse NAK gönderir ve paketi düsürür.
    Duplikat paket gelirse ACK tekrar gönderilir (kaydetmeden).

Teardown:
    FIN paketi alindiktan sonra:
    1. Tüm buffer'daki chunk'lar reassemble_file() ile diske yazilir.
    2. FIN-ACK gönderilir.
    3. MD5 dogrulama sonucu loglanir (eger orijinal yol verilmisse).

select.select() kullanimi:
    Bloklanma olmadan paket beklenir. Dis döngü zaman asiminda graceful
    kapanma yapabilir.
"""

import os
import select
import socket
import time
from typing import Dict, Optional, Tuple

import config
from netprobe.logger import NetLogger
from netprobe.packet import (
    AckPacket,
    DataPacket,
    STATUS_BUFFER_FULL,
    STATUS_NAK,
    STATUS_OK,
    TYPE_ACK,
    TYPE_FIN,
    make_fin_ack_packet,
    make_nak_packet,
    identify_packet,
)
from netprobe.protocol import (
    ProtocolConfig,
    ProtocolMode,
    reassemble_file,
    verify_file_integrity,
)


# ---------------------------------------------------------------------------
# Receiver
# ---------------------------------------------------------------------------

class Receiver:
    """
    UDP üzerinden guvenilir dosya alma motoru.

    Gelen paketleri dogrular, siraya koyar, ACK/NAK üretir ve
    tamamlanan aktarimi diske yazar.

    Attributes:
        _sock        (socket.socket)      : Baglanmis UDP soketi.
        _logger      (NetLogger)          : Olay kayit sistemi.
        _cfg         (ProtocolConfig)     : Protokol konfigürasyonu.
        _client_addr (Tuple[str,int]|None): Ilk paketten sonra belirlenen
                                           gönderici adresi.

    Ornek:
        >>> import socket
        >>> sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        >>> sock.bind(("0.0.0.0", 9000))
        >>> logger = NetLogger()
        >>> cfg = ProtocolConfig()
        >>> receiver = Receiver(sock, logger, cfg)
        >>> receiver.receive_file("alinan.bin")
        >>> logger.close()
    """

    # Dis döngü icin maksimum bekleme süresi (paket araliginda).
    # Bu süre gecerse alici graceful sekilde kapanir.
    _OUTER_TIMEOUT_SEC: float = 30.0

    def __init__(
        self,
        sock: socket.socket,
        logger: NetLogger,
        cfg: ProtocolConfig,
    ) -> None:
        """
        Receiver'i baslatir.

        Args:
            sock   (socket.socket) : Bind edilmis UDP soketi.
            logger (NetLogger)     : Olay kayit sistemi.
            cfg    (ProtocolConfig): Protokol konfigürasyonu.
        """
        self._sock        = sock
        self._logger      = logger
        self._cfg         = cfg
        self._client_addr: Optional[Tuple[str, int]] = None

    # ------------------------------------------------------------------
    # Ana Metod
    # ------------------------------------------------------------------

    def receive_file(
        self,
        output_path: str,
        original_path: Optional[str] = None,
    ) -> Dict:
        """
        Sunucu tarafinda dosya alimini baslatir ve yönetir.

        ProtocolConfig.mode'a göre SAW veya GBN alici algoritmasini secer.
        FIN paketi alininca dosyayi diske yazar, FIN-ACK gönderir ve
        istatistik sözlügünü döndürür.

        Args:
            output_path   (str)          : Alinacak dosyanin yazilacagi yol.
            original_path (str | None)   : MD5 dogrulama icin kaynak dosya yolu.
                                           None verilirse dogrulama atlanir.

        Returns:
            Dict: Aktarim sonuc istatistikleri:
                - ``received_packets``   : Kabul edilen paket sayisi
                - ``dropped_packets``    : Düsürülen paket sayisi
                - ``file_size_bytes``    : Yazilan dosyanin boyutu
                - ``integrity_ok``       : MD5 dogrulama sonucu (bool|None)
                - ``output_path``        : Yazilan dosyanin yolu

        Raises:
            RuntimeError: Belirlenen süre icinde hic paket gelmezse.
        """
        if self._cfg.mode == ProtocolMode.SAW:
            buffer, stats = self._recv_saw()
        else:
            # GBN ve SR icin GBN kullani
            buffer, stats = self._recv_gbn()

        # Dosyayi diske yaz
        written = reassemble_file(buffer, output_path)
        stats["file_size_bytes"] = written
        stats["output_path"]     = output_path

        # FIN-ACK daha once gönderildi (_recv_* icinde).
        # MD5 dogrulama
        integrity: Optional[bool] = None
        if original_path and os.path.isfile(original_path):
            try:
                integrity = verify_file_integrity(original_path, output_path)
                status_str = "OK" if integrity else "FAIL"
                self._logger.log_fin(0.0)  # Alici tarafinda sure bilinmez
            except OSError:
                integrity = None
        stats["integrity_ok"] = integrity

        return stats

    # ------------------------------------------------------------------
    # Stop-and-Wait Alici
    # ------------------------------------------------------------------

    def _recv_saw(self) -> Tuple[Dict[int, bytes], Dict]:
        """
        Stop-and-Wait modunda paket alir.

        Siradaki beklenen seq_num'u kabul eder. Eski ya da duplikat
        paket gelirse ACK yeniden gönderilir ancak buffer'a yazilmaz.

        Akis:
            expected_seq = 0
            döngü:
                paketi bekle (select)
                FIN mi?  -> FIN-ACK gönder, cik
                seq == expected_seq? -> kabul et, ACK gönder, expected_seq++
                seq <  expected_seq? -> duplikat, eski ACK tekrar gönder, log_drop
                seq >  expected_seq? -> out-of-order, NAK gönder, log_drop
                                        (SAW'da normalde olmamali)

        Returns:
            Tuple[Dict[int, bytes], Dict]: (buffer, istatistik sözlügü)
        """
        buffer:        Dict[int, bytes] = {}
        expected_seq:  int              = 0
        received_pkts: int              = 0
        dropped_pkts:  int              = 0
        total_packets: Optional[int]    = None

        while True:
            # Paket bekle
            readable, _, _ = select.select(
                [self._sock], [], [], self._OUTER_TIMEOUT_SEC
            )
            if not readable:
                # Uzun süre paket gelmedi: döngüden cik
                break

            # Ham veriyi al
            try:
                raw, addr = self._sock.recvfrom(config.SOCKET_BUFFER_SIZE)
            except OSError as exc:
                self._logger.log_error(expected_seq, "recvfrom", str(exc))
                continue

            # Ilk paketten gönderici adresini kaydet
            if self._client_addr is None:
                self._client_addr = addr

            # Paket tipini belirle
            try:
                pkt_name, _ = identify_packet(raw)
            except ValueError:
                continue

            if pkt_name not in ("DATA", "FIN"):
                # Yanlis paket tipi (örn. oralarda bir ACK)
                continue

            # DataPacket veya FIN olarak ayristir
            try:
                pkt = DataPacket.from_bytes(raw)
            except ValueError as exc:
                # Checksum veya ayristica hatasi
                self._logger.log_error(expected_seq, "checksum_ok", str(exc))
                # NAK gönder (beklenen seq ile)
                self._send_nak(expected_seq, addr)
                dropped_pkts += 1
                continue

            if total_packets is None:
                total_packets = pkt.total_packets

            # ── FIN: aktarim bitiyor ──────────────────────────────
            if pkt.is_fin:
                self._send_fin_ack(pkt.seq_num, addr)
                break

            seq = pkt.seq_num

            if seq == expected_seq:
                # Dogru paket: kabul et
                buffer[seq] = pkt.payload
                received_pkts += 1
                expected_seq  += 1
                self._send_ack(seq, addr)

            elif seq < expected_seq:
                # Duplikat paket: yeniden ACK gönder, kaydetme
                self._logger.log_drop(seq)
                dropped_pkts += 1
                self._send_ack(seq, addr)

            else:
                # Out-of-order paket (SAW'da normalde olmamali): NAK
                self._logger.log_drop(seq)
                dropped_pkts += 1
                self._send_nak(expected_seq, addr)

        return buffer, {
            "received_packets": received_pkts,
            "dropped_packets":  dropped_pkts,
        }

    # ------------------------------------------------------------------
    # Go-Back-N Alici
    # ------------------------------------------------------------------

    def _recv_gbn(self) -> Tuple[Dict[int, bytes], Dict]:
        """
        Go-Back-N modunda paket alir.

        GBN alicisi yalnizca beklenen seq_num'u kabul eder (in-order).
        Beklenen disindaki paketler NAK ile reddedilir ve düsürülür.
        Duplikat paketler log_drop ile isaret edilir, ACK tekrar gönderilir.

        Akis:
            expected_seq = 0
            döngü:
                paketi bekle (select)
                FIN mi?  -> FIN-ACK gönder, cik
                seq == expected_seq? -> kabul et, ACK gönder, expected_seq++
                seq <  expected_seq? -> duplikat, eski ACK tekrar gönder, log_drop
                seq >  expected_seq? -> out-of-order, NAK(expected_seq), log_drop

        Returns:
            Tuple[Dict[int, bytes], Dict]: (buffer, istatistik sözlügü)
        """
        buffer:        Dict[int, bytes] = {}
        expected_seq:  int              = 0
        received_pkts: int              = 0
        dropped_pkts:  int              = 0
        total_packets: Optional[int]    = None

        while True:
            # Paket bekle
            readable, _, _ = select.select(
                [self._sock], [], [], self._OUTER_TIMEOUT_SEC
            )
            if not readable:
                break

            try:
                raw, addr = self._sock.recvfrom(config.SOCKET_BUFFER_SIZE)
            except OSError as exc:
                self._logger.log_error(expected_seq, "recvfrom", str(exc))
                continue

            if self._client_addr is None:
                self._client_addr = addr

            # Paket tipini belirle
            try:
                pkt_name, _ = identify_packet(raw)
            except ValueError:
                continue

            if pkt_name not in ("DATA", "FIN"):
                continue

            # Ayristir
            try:
                pkt = DataPacket.from_bytes(raw)
            except ValueError as exc:
                # Bozuk paket: NAK gönder
                self._logger.log_error(expected_seq, "checksum_ok", str(exc))
                self._send_nak(expected_seq, addr)
                dropped_pkts += 1
                continue

            if total_packets is None:
                total_packets = pkt.total_packets

            # ── FIN ──────────────────────────────────────────────
            if pkt.is_fin:
                self._send_fin_ack(pkt.seq_num, addr)
                break

            seq = pkt.seq_num

            if seq == expected_seq:
                # Beklenen paket: kabul et
                buffer[seq] = pkt.payload
                received_pkts += 1
                expected_seq  += 1
                self._send_ack(seq, addr)

            elif seq < expected_seq:
                # Duplikat paket: ACK tekrar gönder, kaydetme
                self._logger.log_drop(seq)
                dropped_pkts += 1
                self._send_ack(seq, addr)   # göndericiyi bilgilendir

            else:
                # Out-of-order paket: GBN kabul etmez, NAK gönder
                self._logger.log_drop(seq)
                dropped_pkts += 1
                self._send_nak(expected_seq, addr)  # beklenen seq ile NAK

        return buffer, {
            "received_packets": received_pkts,
            "dropped_packets":  dropped_pkts,
        }

    # ------------------------------------------------------------------
    # ACK / NAK / FIN-ACK Gönderme Yardimcilari
    # ------------------------------------------------------------------

    def _send_ack(self, seq_num: int, addr: Tuple[str, int]) -> None:
        """
        Belirtilen seq_num icin ACK paketi gönderir.

        Args:
            seq_num (int)         : Onaylanan sira numarasi.
            addr    (tuple[str,int]): Gönderilecek hedef adres.
        """
        ack = AckPacket(
            ack_num=seq_num,
            status=STATUS_OK,
            recv_window=self._cfg.window_size,
        )
        try:
            self._sock.sendto(ack.to_bytes(), addr)
        except OSError as exc:
            self._logger.log_error(seq_num, "ack_send", str(exc))

    def _send_nak(self, expected_seq: int, addr: Tuple[str, int]) -> None:
        """
        Beklenen sira numarasini bildiren NAK paketi gönderir.

        Args:
            expected_seq (int)         : Alinmasi beklenen sira numarasi.
            addr         (tuple[str,int]): Gönderilecek hedef adres.
        """
        nak = AckPacket(
            ack_num=expected_seq,
            status=STATUS_NAK,
            recv_window=self._cfg.window_size,
        )
        try:
            self._sock.sendto(nak.to_bytes(), addr)
        except OSError as exc:
            self._logger.log_error(expected_seq, "nak_send", str(exc))

    def _send_fin_ack(self, fin_seq: int, addr: Tuple[str, int]) -> None:
        """
        FIN paketine karsilik FIN-ACK gönderir.

        Args:
            fin_seq (int)          : Alinan FIN paketinin sira numarasi.
            addr    (tuple[str,int]): Gönderilecek hedef adres.
        """
        fin_ack = make_fin_ack_packet(ack_num=fin_seq)
        try:
            self._sock.sendto(fin_ack.to_bytes(), addr)
        except OSError as exc:
            self._logger.log_error(-1, "fin_ack_send", str(exc))

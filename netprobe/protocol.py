# -*- coding: utf-8 -*-
"""
netprobe/protocol.py
====================
NetProbe -- UDP Tabanli Guvenilir Dosya Aktarim Sistemi
Bursa Teknik Universitesi | Bilgisayar Aglari Dersi

Protokol modu tanimlari, konfigürasyon dataclass'i ve dosya islem
yardimcilari bu modulde toplanmistir.

Disari aktarilan semboller:
    ProtocolMode     -- SAW / GBN / SR enum
    ProtocolConfig   -- tek noktadan konfigürasyon dataclass'i
    split_file       -- dosyayi chunk'lara böler
    reassemble_file  -- chunk sozlügunden dosyayi diske yazar
    verify_file_integrity -- MD5 ile iki dosyayi karsilastirir
"""

import hashlib
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple

import config


# ---------------------------------------------------------------------------
# ProtocolMode -- Protokol Modu
# ---------------------------------------------------------------------------

class ProtocolMode(Enum):
    """
    Desteklenen guvenilir aktarim protokol modlari.

    Degerler:
        SAW : Stop-and-Wait. Pencere boyutu 1'e zorlanir.
              Her paketin ACK'i alinmadan bir sonraki gönderilmez.
        GBN : Go-Back-N. Hata aliminda penceredeki tüm paketler
              yeniden gönderilir. Alici sadece siradaki paketi kabul eder.
        SR  : Selective Repeat. Sadece kayip/hatali paket yeniden
              gönderilir. Alici pencere icindeki paketleri tamponlar.
              (Bu surum SAW ve GBN'yi tam olarak implemente eder;
               SR icin receiver tarafinda ek buffer mantigi gerekir.)
    """
    SAW = "SAW"
    GBN = "GBN"
    SR  = "SR"


# ---------------------------------------------------------------------------
# ProtocolConfig -- Protokol Konfigürasyonu
# ---------------------------------------------------------------------------

@dataclass
class ProtocolConfig:
    """
    Protokol parametrelerini config.py'den okuyarak tek bir nesnede toplar.

    Bu sinif tüm bilesenler (Sender, Receiver, Simulator) tarafindan
    ortak olarak kullanilir; boylece konfigürasyon tek yerden yönetilir.

    Attributes:
        chunk_size   (int)         : Tek paketteki max veri boyutu (byte).
        window_size  (int)         : Sliding window boyutu (paket sayisi).
                                     SAW modunda otomatik olarak 1'e set edilir.
        timeout_sec  (float)       : ACK icin bekleme süresi (saniye).
        max_retries  (int)         : Tek paket icin max yeniden gönderim.
        mode         (ProtocolMode): Aktif protokol modu.

    Ornek:
        >>> cfg = ProtocolConfig()
        >>> cfg.mode
        <ProtocolMode.GBN: 'GBN'>
        >>> cfg.window_size
        4

        >>> cfg_saw = ProtocolConfig(mode=ProtocolMode.SAW)
        >>> cfg_saw.window_size  # SAW'da 1'e zorlanir
        1
    """
    chunk_size:  int          = field(default_factory=lambda: config.CHUNK_SIZE)
    window_size: int          = field(default_factory=lambda: config.WINDOW_SIZE)
    timeout_sec: float        = field(default_factory=lambda: config.TIMEOUT_SEC)
    max_retries: int          = field(default_factory=lambda: config.MAX_RETRIES)
    mode:        ProtocolMode = field(
        default_factory=lambda: ProtocolMode(config.MODE)
    )

    def __post_init__(self) -> None:
        """
        Deger dogrulamasi ve mod bazli düzeltmeler yapar.

        SAW modunda window_size 1'e zorunlu olarak ayarlanir.
        Diger parametreler mantik araligi kontrolünden gecirilir.

        Raises:
            ValueError: chunk_size <= 0, timeout_sec <= 0 veya max_retries < 1 ise.
        """
        if self.chunk_size <= 0:
            raise ValueError(f"chunk_size pozitif olmalidir, alindi: {self.chunk_size}")
        if self.timeout_sec <= 0:
            raise ValueError(f"timeout_sec pozitif olmalidir, alindi: {self.timeout_sec}")
        if self.max_retries < 1:
            raise ValueError(f"max_retries en az 1 olmalidir, alindi: {self.max_retries}")

        # SAW modunda pencere boyutu 1'e zorlanir
        if self.mode == ProtocolMode.SAW:
            self.window_size = 1


# ---------------------------------------------------------------------------
# split_file -- Dosyayi Chunk'lara Böl
# ---------------------------------------------------------------------------

def split_file(filepath: str, chunk_size: int) -> List[Tuple[int, bytes]]:
    """
    Verilen dosyayi ``chunk_size`` byte'lik parcalara böler.

    Her parca bir (seq_num, payload) demeti olarak döndürülür.
    seq_num 0'dan baslar ve her parca icin 1 artar.
    Son parca ``chunk_size``'dan küçük olabilir.

    Args:
        filepath   (str): Okunacak dosyanin tam yolu.
        chunk_size (int): Her parcanin maksimum boyutu (byte).

    Returns:
        List[Tuple[int, bytes]]: (seq_num, payload) demetlerinin listesi.
                                  Liste sirasi dosya sirasiyla eslesir.

    Raises:
        FileNotFoundError : Dosya bulunamazsa.
        ValueError        : chunk_size <= 0 ise.
        IOError           : Dosya okunamazsa.

    Ornek:
        >>> chunks = split_file("ornek.bin", chunk_size=1024)
        >>> seq0, payload0 = chunks[0]
        >>> seq0
        0
        >>> len(payload0) <= 1024
        True
    """
    if chunk_size <= 0:
        raise ValueError(f"chunk_size pozitif olmalidir: {chunk_size}")
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Dosya bulunamadi: {filepath}")

    chunks: List[Tuple[int, bytes]] = []
    seq_num = 0

    with open(filepath, "rb") as fh:
        while True:
            payload = fh.read(chunk_size)
            if not payload:
                break
            chunks.append((seq_num, payload))
            seq_num += 1

    return chunks


# ---------------------------------------------------------------------------
# reassemble_file -- Chunk Sozlügünden Dosyayi Olustur
# ---------------------------------------------------------------------------

def reassemble_file(chunks: Dict[int, bytes], output_path: str) -> int:
    """
    Seq numarasina göre sirali chunk'lari birlestirerek dosyayi diske yazar.

    Eksik seq numaralari atlanir (kayip paket durumu). Hedef dizin yoksa
    otomatik olarak olusturulur.

    Args:
        chunks      (Dict[int, bytes]): {seq_num: payload} sozlügü.
        output_path (str)             : Olusturulacak dosyanin tam yolu.

    Returns:
        int: Diske yazilan toplam byte sayisi.

    Raises:
        IOError: Dosya yazma hatasi olusursa.

    Ornek:
        >>> chunks = {0: b"merhaba ", 1: b"dunya"}
        >>> n = reassemble_file(chunks, "cikti.bin")
        >>> n
        13
    """
    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    total_written = 0
    with open(output_path, "wb") as fh:
        for seq in sorted(chunks.keys()):
            fh.write(chunks[seq])
            total_written += len(chunks[seq])

    return total_written


# ---------------------------------------------------------------------------
# verify_file_integrity -- MD5 ile Dosya Dogrulama
# ---------------------------------------------------------------------------

def verify_file_integrity(original_path: str, received_path: str) -> bool:
    """
    Iki dosyanin MD5 ozet degerlerini karsilastirir.

    Aktarim tamamlandiktan sonra alinan dosyanin kaynak dosyayla birebir
    ayni oldugunu dogrulamak icin kullanilir. Her iki dosya da blok blok
    okunarak büyük dosyalarda bellek tasarrufu saglanir.

    Args:
        original_path (str): Kaynak dosyanin tam yolu (gönderici tarafinda).
        received_path (str): Alinan dosyanin tam yolu (alici tarafinda).

    Returns:
        bool: MD5 özetleri eslesiyorsa True, farkli ise False.

    Raises:
        FileNotFoundError: Dosyalardan biri veya ikisi bulunamazsa.

    Ornek:
        >>> verify_file_integrity("orijinal.bin", "alinan.bin")
        True
    """
    def _md5(path: str) -> str:
        """Dosyanin MD5 ozet degerini hesaplar (blok blok okur)."""
        h = hashlib.md5()
        with open(path, "rb") as fh:
            for blok in iter(lambda: fh.read(65536), b""):
                h.update(blok)
        return h.hexdigest()

    digest_orig = _md5(original_path)
    digest_recv = _md5(received_path)
    return digest_orig == digest_recv

# -*- coding: utf-8 -*-
"""
tests/test_packet.py
====================
NetProbe -- packet.py birim testleri.

Calistirmak icin:
    python -m pytest tests/test_packet.py -v
    # veya
    python tests/test_packet.py
"""

import os
import sys
import struct
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netprobe.packet import (
    AckPacket,
    DataPacket,
    DATA_HEADER_SIZE,
    ACK_HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    TYPE_DATA, TYPE_ACK, TYPE_FIN, TYPE_FIN_ACK,
    STATUS_OK, STATUS_NAK, STATUS_BUFFER_FULL,
    compute_checksum,
    verify_checksum,
    make_fin_packet,
    make_fin_ack_packet,
    make_nak_packet,
    identify_packet,
)


# ---------------------------------------------------------------------------
# DataPacket Testleri
# ---------------------------------------------------------------------------

class TestDataPacket(unittest.TestCase):
    """DataPacket serializasyon, dogrulama ve ozellik testleri."""

    def _make(self, seq=0, total=10, payload=b"hello", pkt_type=TYPE_DATA):
        return DataPacket(seq_num=seq, total_packets=total,
                          payload=payload, pkt_type=pkt_type)

    # -- Round-trip --
    def test_round_trip_normal_payload(self):
        """Tipik payload ile to_bytes/from_bytes dongusu kayipsiz olmali."""
        pkt = self._make(seq=42, total=100, payload=b"A" * 512)
        restored = DataPacket.from_bytes(pkt.to_bytes())
        self.assertEqual(restored.seq_num,       42)
        self.assertEqual(restored.total_packets, 100)
        self.assertEqual(restored.payload,       b"A" * 512)
        self.assertEqual(restored.pkt_type,      TYPE_DATA)

    def test_round_trip_full_payload(self):
        """Maksimum boyutta (1024 byte) payload dogru aktarilmali."""
        payload = bytes(range(256)) * 4   # 1024 byte
        pkt = self._make(payload=payload)
        restored = DataPacket.from_bytes(pkt.to_bytes())
        self.assertEqual(restored.payload, payload)

    def test_round_trip_empty_payload(self):
        """Sifir byte payload (son paket senaryosu) desteklenmeli."""
        pkt = self._make(payload=b"")
        restored = DataPacket.from_bytes(pkt.to_bytes())
        self.assertEqual(restored.payload, b"")
        self.assertFalse(restored.is_fin)

    def test_round_trip_single_byte(self):
        """Tek byte payload dogru serileşmeli."""
        pkt = self._make(payload=b"\xFF")
        restored = DataPacket.from_bytes(pkt.to_bytes())
        self.assertEqual(restored.payload, b"\xFF")

    def test_round_trip_binary_data(self):
        """Tüm byte degerleri (0x00-0xFF) ic ice gecmis veri dogru aktarilmali."""
        payload = bytes(range(256))
        pkt = self._make(payload=payload)
        restored = DataPacket.from_bytes(pkt.to_bytes())
        self.assertEqual(restored.payload, payload)

    # -- Header boyutu --
    def test_header_size_constant(self):
        """DATA_HEADER_SIZE her zaman 13 byte olmali."""
        self.assertEqual(DATA_HEADER_SIZE, 13)

    def test_packet_size_property(self):
        """size property = baslík + payload boyutu olmali."""
        pkt = self._make(payload=b"X" * 200)
        self.assertEqual(pkt.size, DATA_HEADER_SIZE + 200)

    # -- FIN paketi --
    def test_fin_packet_type(self):
        """FIN paketi is_fin=True, TYPE_FIN olmali."""
        fin = self._make(pkt_type=TYPE_FIN, payload=b"")
        self.assertTrue(fin.is_fin)
        self.assertEqual(fin.pkt_type, TYPE_FIN)

    def test_fin_round_trip(self):
        """FIN paketi to_bytes/from_bytes sonrasi tipi korunmali."""
        fin = make_fin_packet(seq_num=99, total_packets=99)
        restored = DataPacket.from_bytes(fin.to_bytes())
        self.assertTrue(restored.is_fin)
        self.assertEqual(restored.seq_num, 99)
        self.assertEqual(restored.payload, b"")

    # -- Checksum --
    def test_checksum_embedded_correctly(self):
        """to_bytes() sonucunda gömülü checksum dogru olmali."""
        pkt = self._make(payload=b"test verisi")
        raw = pkt.to_bytes()
        # Struct format: ! B I I H H
        # TYPE(1) + SEQ(4) + TOTAL(4) + PAYLOAD_LEN(2) + CHECKSUM(2) = 13 byte
        # Checksum alani: byte 11 ve 12 (0-indexli)
        CHECKSUM_OFFSET = 1 + 4 + 4 + 2   # = 11
        crc_in_pkt = struct.unpack("!H", raw[CHECKSUM_OFFSET:CHECKSUM_OFFSET + 2])[0]
        # Checksum sifirlanmis baslik + payload üzerinde yeniden hesapla
        header_zeroed = (
            raw[:CHECKSUM_OFFSET]
            + b"\x00\x00"
            + raw[CHECKSUM_OFFSET + 2:DATA_HEADER_SIZE]
        )
        expected = compute_checksum(header_zeroed + pkt.payload)
        self.assertEqual(crc_in_pkt, expected)

    def test_bad_checksum_raises(self):
        """Bozulmus checksum ValueError firlat mali."""
        raw = bytearray(self._make(payload=b"test").to_bytes())
        raw[9] ^= 0xFF    # checksum byte'ini boz
        with self.assertRaises(ValueError):
            DataPacket.from_bytes(bytes(raw))

    def test_bad_type_raises(self):
        """Yanlis paket tipi (ACK) DATA.from_bytes'ta hata firlat mali."""
        ack = AckPacket(ack_num=0, status=STATUS_OK, recv_window=4)
        with self.assertRaises(ValueError):
            DataPacket.from_bytes(ack.to_bytes())

    def test_too_short_raises(self):
        """Cok kisa (baslik eksik) veri ValueError firlat mali."""
        with self.assertRaises(ValueError):
            DataPacket.from_bytes(b"\x01\x00")

    # -- Deger siniriari --
    def test_payload_too_large_raises(self):
        """MAX_PAYLOAD_SIZE'dan büyük payload kabul edilmemeli."""
        with self.assertRaises(ValueError):
            DataPacket(seq_num=0, total_packets=1,
                       payload=b"X" * (MAX_PAYLOAD_SIZE + 1))

    def test_seq_num_boundary(self):
        """Maksimum uint32 seq_num (2^32 - 1) desteklenmeli."""
        pkt = DataPacket(seq_num=0xFFFF_FFFF, total_packets=1, payload=b"x")
        restored = DataPacket.from_bytes(pkt.to_bytes())
        self.assertEqual(restored.seq_num, 0xFFFF_FFFF)


# ---------------------------------------------------------------------------
# AckPacket Testleri
# ---------------------------------------------------------------------------

class TestAckPacket(unittest.TestCase):
    """AckPacket serializasyon, durum ve ozellik testleri."""

    # -- Round-trip --
    def test_round_trip_ok(self):
        """STATUS_OK ACK paketi kayipsiz aktarilmali."""
        ack = AckPacket(ack_num=7, status=STATUS_OK, recv_window=4)
        restored = AckPacket.from_bytes(ack.to_bytes())
        self.assertEqual(restored.ack_num,     7)
        self.assertEqual(restored.status,      STATUS_OK)
        self.assertEqual(restored.recv_window, 4)
        self.assertFalse(restored.is_nak)
        self.assertFalse(restored.is_fin_ack)
        self.assertFalse(restored.is_buffer_full)

    def test_round_trip_nak(self):
        """STATUS_NAK ACK paketi is_nak=True döndürmeli."""
        nak = make_nak_packet(expected_seq=5, recv_window=2)
        restored = AckPacket.from_bytes(nak.to_bytes())
        self.assertTrue(restored.is_nak)
        self.assertEqual(restored.ack_num, 5)

    def test_round_trip_buffer_full(self):
        """STATUS_BUFFER_FULL is_buffer_full=True döndürmeli."""
        ack = AckPacket(ack_num=3, status=STATUS_BUFFER_FULL, recv_window=0)
        restored = AckPacket.from_bytes(ack.to_bytes())
        self.assertTrue(restored.is_buffer_full)

    def test_round_trip_fin_ack(self):
        """FIN-ACK paketi is_fin_ack=True olmali."""
        finack = make_fin_ack_packet(ack_num=100)
        restored = AckPacket.from_bytes(finack.to_bytes())
        self.assertTrue(restored.is_fin_ack)
        self.assertEqual(restored.ack_num, 100)

    # -- Header boyutu --
    def test_header_size_constant(self):
        """ACK_HEADER_SIZE her zaman 10 byte olmali."""
        self.assertEqual(ACK_HEADER_SIZE, 10)

    def test_ack_packet_exact_size(self):
        """ACK paketi her zaman sabit 10 byte olmali."""
        ack = AckPacket(ack_num=0, status=STATUS_OK, recv_window=0)
        self.assertEqual(len(ack.to_bytes()), ACK_HEADER_SIZE)

    # -- Checksum --
    def test_bad_ack_checksum_raises(self):
        """ACK paketi bozulmus checksum ValueError firlat mali."""
        raw = bytearray(AckPacket(ack_num=5, status=STATUS_OK, recv_window=1).to_bytes())
        raw[8] ^= 0xAA
        with self.assertRaises(ValueError):
            AckPacket.from_bytes(bytes(raw))

    def test_wrong_type_in_ack_raises(self):
        """DATA paketi ACK.from_bytes'ta hata firlat mali."""
        data_pkt = DataPacket(seq_num=0, total_packets=1, payload=b"x")
        with self.assertRaises(ValueError):
            AckPacket.from_bytes(data_pkt.to_bytes())

    def test_too_short_ack_raises(self):
        """Eksik ACK verisi ValueError firlat mali."""
        with self.assertRaises(ValueError):
            AckPacket.from_bytes(b"\x02\x00")

    # -- Deger siniriari --
    def test_invalid_status_raises(self):
        """Tanimli olmayan status kodu kabul edilmemeli."""
        with self.assertRaises(ValueError):
            AckPacket(ack_num=0, status=0x42, recv_window=0)


# ---------------------------------------------------------------------------
# Checksum Testleri
# ---------------------------------------------------------------------------

class TestChecksum(unittest.TestCase):
    """compute_checksum ve verify_checksum birim testleri."""

    def test_compute_returns_uint16(self):
        """Checksum 0-65535 araliginda olmali."""
        cs = compute_checksum(b"test")
        self.assertGreaterEqual(cs, 0)
        self.assertLessEqual(cs, 0xFFFF)

    def test_same_data_same_checksum(self):
        """Ayni veri her zaman ayni checksum'u vermeli (deterministik)."""
        data = b"bursa teknik universitesi"
        self.assertEqual(compute_checksum(data), compute_checksum(data))

    def test_different_data_different_checksum(self):
        """Farkli veri farkli checksum'u vermeli (cok yüksek olasilikla)."""
        cs1 = compute_checksum(b"paket1")
        cs2 = compute_checksum(b"paket2")
        self.assertNotEqual(cs1, cs2)

    def test_verify_correct(self):
        """Dogru checksum dogrulama True döndürmeli."""
        data = b"dogrulama testi"
        cs   = compute_checksum(data)
        self.assertTrue(verify_checksum(data, cs))

    def test_verify_wrong(self):
        """Yanlis checksum dogrulama False döndürmeli."""
        data = b"dogrulama testi"
        cs   = compute_checksum(data)
        self.assertFalse(verify_checksum(data, cs ^ 0xFFFF))

    def test_verify_empty_data(self):
        """Bos veri icin checksum hesaplanabilmeli."""
        cs = compute_checksum(b"")
        self.assertTrue(verify_checksum(b"", cs))

    def test_single_bit_flip_detected(self):
        """Tek bit degisimi checksum tarafindan yakalanmali."""
        data = bytearray(b"orijinal veri")
        cs   = compute_checksum(bytes(data))
        data[3] ^= 0x01
        self.assertFalse(verify_checksum(bytes(data), cs))


# ---------------------------------------------------------------------------
# Fabrika Fonksiyon Testleri
# ---------------------------------------------------------------------------

class TestFactoryFunctions(unittest.TestCase):
    """make_fin_packet, make_fin_ack_packet, make_nak_packet testleri."""

    def test_make_fin_packet_type(self):
        """make_fin_packet TYPE_FIN ile DataPacket döndürmeli."""
        fin = make_fin_packet(seq_num=50, total_packets=50)
        self.assertEqual(fin.pkt_type, TYPE_FIN)
        self.assertTrue(fin.is_fin)
        self.assertEqual(fin.payload, b"")

    def test_make_fin_packet_round_trip(self):
        """FIN paketi serileştirme sonrasi tipi korunmali."""
        fin = make_fin_packet(seq_num=200, total_packets=200)
        r   = DataPacket.from_bytes(fin.to_bytes())
        self.assertEqual(r.pkt_type, TYPE_FIN)
        self.assertEqual(r.seq_num,  200)

    def test_make_fin_ack_packet_type(self):
        """make_fin_ack_packet TYPE_FIN_ACK ile AckPacket döndürmeli."""
        fa = make_fin_ack_packet(ack_num=200)
        self.assertEqual(fa.pkt_type, TYPE_FIN_ACK)
        self.assertTrue(fa.is_fin_ack)
        self.assertEqual(fa.ack_num, 200)

    def test_make_fin_ack_round_trip(self):
        """FIN-ACK paketi serileştirme sonrasi tipi korunmali."""
        fa = make_fin_ack_packet(ack_num=77)
        r  = AckPacket.from_bytes(fa.to_bytes())
        self.assertEqual(r.pkt_type, TYPE_FIN_ACK)
        self.assertEqual(r.ack_num,  77)

    def test_make_nak_packet_status(self):
        """make_nak_packet STATUS_NAK ile AckPacket döndürmeli."""
        nak = make_nak_packet(expected_seq=3, recv_window=2)
        self.assertEqual(nak.status,      STATUS_NAK)
        self.assertEqual(nak.ack_num,     3)
        self.assertEqual(nak.recv_window, 2)
        self.assertTrue(nak.is_nak)

    def test_make_nak_default_window(self):
        """make_nak_packet varsayilan recv_window=0 olmali."""
        nak = make_nak_packet(expected_seq=0)
        self.assertEqual(nak.recv_window, 0)


# ---------------------------------------------------------------------------
# identify_packet Testleri
# ---------------------------------------------------------------------------

class TestIdentifyPacket(unittest.TestCase):
    """identify_packet yardimci fonksiyon testleri."""

    def test_identify_data(self):
        raw = DataPacket(seq_num=0, total_packets=1, payload=b"x").to_bytes()
        name, code = identify_packet(raw)
        self.assertEqual(name, "DATA")
        self.assertEqual(code, TYPE_DATA)

    def test_identify_ack(self):
        raw = AckPacket(ack_num=0, status=STATUS_OK, recv_window=1).to_bytes()
        name, code = identify_packet(raw)
        self.assertEqual(name, "ACK")
        self.assertEqual(code, TYPE_ACK)

    def test_identify_fin(self):
        raw = make_fin_packet(seq_num=5, total_packets=5).to_bytes()
        name, code = identify_packet(raw)
        self.assertEqual(name, "FIN")
        self.assertEqual(code, TYPE_FIN)

    def test_identify_fin_ack(self):
        raw = make_fin_ack_packet(ack_num=5).to_bytes()
        name, code = identify_packet(raw)
        self.assertEqual(name, "FIN_ACK")
        self.assertEqual(code, TYPE_FIN_ACK)

    def test_identify_unknown(self):
        raw = b"\xDE" + b"\x00" * 10
        name, _ = identify_packet(raw)
        self.assertEqual(name, "UNKNOWN")

    def test_identify_empty_raises(self):
        with self.assertRaises(ValueError):
            identify_packet(b"")


# ---------------------------------------------------------------------------
# Giris Noktasi
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)

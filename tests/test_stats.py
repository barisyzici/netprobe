# -*- coding: utf-8 -*-
"""
tests/test_stats.py
===================
NetProbe -- stats.py birim testleri.

Calistirmak icin:
    python -m pytest tests/test_stats.py -v
    # veya
    python tests/test_stats.py
"""

import os
import sys
import unittest
from typing import List, Optional
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netprobe.logger import EventType, LogEntry
from netprobe.stats  import StatsCalculator


# ---------------------------------------------------------------------------
# Mock Logger
# ---------------------------------------------------------------------------

class MockLogger:
    """
    StatsCalculator testleri icin sahte Logger nesnesi.

    Gercek NetLogger baslatmadan (dosya yazmadan) olay listesi saglar.
    get_events() metodunu destekler.
    """

    def __init__(self, events: Optional[List[LogEntry]] = None) -> None:
        self._events = events or []

    def get_events(self, event_type: Optional[EventType] = None) -> List[LogEntry]:
        """EventType'a göre filtrelenmiş olay listesi döner."""
        if event_type is None:
            return list(self._events)
        return [e for e in self._events if e.event_type == event_type]

    @staticmethod
    def make_entry(
        event_type: EventType,
        seq_num: int = 0,
        timestamp: float = 1000.0,
        **details,
    ) -> LogEntry:
        """Test icin LogEntry kolayca olusturmaya yarayan yardimci."""
        return LogEntry(
            timestamp=timestamp,
            event_type=event_type,
            seq_num=seq_num,
            details=dict(details),
        )


def _make_calc(events: Optional[List[LogEntry]] = None) -> StatsCalculator:
    """Verilen olay listesiyle bir StatsCalculator olusturur."""
    return StatsCalculator(MockLogger(events))


# ---------------------------------------------------------------------------
# Throughput Testleri
# ---------------------------------------------------------------------------

class TestThroughput(unittest.TestCase):
    """throughput() formül dogrulama testleri."""

    def test_basic_calculation(self):
        """10500 byte / 2.1 s = 5000.0 Bps olmali."""
        calc = _make_calc()
        self.assertAlmostEqual(calc.throughput(10500, 2.1), 5000.0, places=2)

    def test_zero_time_returns_zero(self):
        """completion_time_s = 0 iken sifira bölme olmamali, 0.0 döndürmeli."""
        calc = _make_calc()
        self.assertEqual(calc.throughput(9999, 0), 0.0)
        self.assertEqual(calc.throughput(9999, 0.0), 0.0)

    def test_negative_time_returns_zero(self):
        """Negatif süre sifira bölme denememelidir."""
        calc = _make_calc()
        self.assertEqual(calc.throughput(1000, -1.0), 0.0)

    def test_zero_bytes(self):
        """Sifir byte gönderilmisse throughput 0.0 olmali."""
        calc = _make_calc()
        self.assertAlmostEqual(calc.throughput(0, 5.0), 0.0)

    def test_large_transfer(self):
        """100 MB / 10 s = 10 MB/s = 10 485 760 Bps olmali."""
        calc  = _make_calc()
        bytes_100mb = 100 * 1024 * 1024
        result = calc.throughput(bytes_100mb, 10.0)
        self.assertAlmostEqual(result, bytes_100mb / 10.0, places=1)


# ---------------------------------------------------------------------------
# Goodput Testleri
# ---------------------------------------------------------------------------

class TestGoodput(unittest.TestCase):
    """goodput() formül dogrulama testleri."""

    def test_basic_calculation(self):
        """5120 byte / 2.0 s = 2560 Bps olmali."""
        calc = _make_calc()
        self.assertAlmostEqual(calc.goodput(5120, 2.0), 2560.0, places=2)

    def test_goodput_leq_throughput(self):
        """Goodput her zaman throughput'tan küçük veya esit olmali."""
        calc = _make_calc()
        tp = calc.throughput(11000, 3.0)
        gp = calc.goodput(10000, 3.0)
        self.assertLessEqual(gp, tp)

    def test_zero_time_returns_zero(self):
        """Sifir süre icin sifira bölme olmamali."""
        calc = _make_calc()
        self.assertEqual(calc.goodput(5000, 0), 0.0)

    def test_equal_when_no_overhead(self):
        """Başlik yoksa goodput == throughput olmali."""
        calc = _make_calc()
        self.assertAlmostEqual(
            calc.goodput(1000, 1.0),
            calc.throughput(1000, 1.0),
        )


# ---------------------------------------------------------------------------
# Packet Loss Rate Testleri
# ---------------------------------------------------------------------------

class TestPacketLossRate(unittest.TestCase):
    """packet_loss_rate() yüzde hesabi ve sinir durumlari."""

    def test_no_loss(self):
        """Kayip yoksa %0 olmali."""
        self.assertAlmostEqual(_make_calc().packet_loss_rate(100, 0), 0.0)

    def test_full_loss(self):
        """Tüm paketler kayipsa %100 olmali."""
        self.assertAlmostEqual(_make_calc().packet_loss_rate(50, 50), 100.0)

    def test_ten_percent(self):
        """100 paketten 10'u kayipsa %10 olmali."""
        self.assertAlmostEqual(
            _make_calc().packet_loss_rate(100, 10), 10.0, places=4
        )

    def test_five_percent(self):
        """200 paketten 10'u kayipsa %5 olmali."""
        self.assertAlmostEqual(
            _make_calc().packet_loss_rate(200, 10), 5.0, places=4
        )

    def test_zero_total_returns_zero(self):
        """total_sent=0 iken sifira bölme olmamali."""
        self.assertEqual(_make_calc().packet_loss_rate(0, 0), 0.0)
        self.assertEqual(_make_calc().packet_loss_rate(0, 5), 0.0)

    def test_result_in_percent(self):
        """Sonuc 0-100 araliginda olmali."""
        rate = _make_calc().packet_loss_rate(1000, 300)
        self.assertGreaterEqual(rate, 0.0)
        self.assertLessEqual(rate, 100.0)


# ---------------------------------------------------------------------------
# Retransmission Rate Testleri
# ---------------------------------------------------------------------------

class TestRetransmissionRate(unittest.TestCase):
    """retransmission_rate() yüzde hesabi testleri."""

    def test_no_retransmit(self):
        """Yeniden gönderim yoksa %0 olmali."""
        self.assertAlmostEqual(_make_calc().retransmission_rate(100, 0), 0.0)

    def test_twenty_percent(self):
        """100 paketten 20'si yeniden gönderilmisse %20 olmali."""
        self.assertAlmostEqual(
            _make_calc().retransmission_rate(100, 20), 20.0, places=4
        )

    def test_can_exceed_100_percent(self):
        """GBN'de retransmit > total_sent olabilir (>%100 kabul edilmeli)."""
        rate = _make_calc().retransmission_rate(10, 30)
        self.assertAlmostEqual(rate, 300.0, places=4)

    def test_zero_total_returns_zero(self):
        """total_sent=0 iken sifira bölme olmamali."""
        self.assertEqual(_make_calc().retransmission_rate(0, 0), 0.0)


# ---------------------------------------------------------------------------
# Average RTT Testleri
# ---------------------------------------------------------------------------

class TestAverageRTT(unittest.TestCase):
    """average_rtt() logger'dan RTT okuma testleri."""

    def _make_ack_events(self, rtts: List[float]) -> List[LogEntry]:
        return [
            MockLogger.make_entry(EventType.ACK_RECV, seq_num=i, rtt_ms=r)
            for i, r in enumerate(rtts)
        ]

    def test_basic_average(self):
        """[10, 20, 30] ms -> ort = 20.0 ms olmali."""
        events = self._make_ack_events([10.0, 20.0, 30.0])
        calc   = _make_calc(events)
        self.assertAlmostEqual(calc.average_rtt(), 20.0, places=3)

    def test_single_ack(self):
        """Tek ACK olayinda ortalama o degere esit olmali."""
        events = self._make_ack_events([42.5])
        self.assertAlmostEqual(_make_calc(events).average_rtt(), 42.5, places=3)

    def test_no_ack_events_returns_zero(self):
        """ACK_RECV olayi yokken 0.0 döndürmeli."""
        events = [MockLogger.make_entry(EventType.SEND, seq_num=0)]
        self.assertEqual(_make_calc(events).average_rtt(), 0.0)

    def test_empty_logger_returns_zero(self):
        """Hic olay yokken 0.0 döndürmeli."""
        self.assertEqual(_make_calc([]).average_rtt(), 0.0)

    def test_mixed_events_only_ack_counted(self):
        """Karísik olaylar arasinda sadece ACK_RECV RTT hesabina katilmali."""
        events = [
            MockLogger.make_entry(EventType.SEND,       seq_num=0),
            MockLogger.make_entry(EventType.ACK_RECV,   seq_num=0, rtt_ms=15.0),
            MockLogger.make_entry(EventType.TIMEOUT,    seq_num=1),
            MockLogger.make_entry(EventType.ACK_RECV,   seq_num=1, rtt_ms=25.0),
            MockLogger.make_entry(EventType.RETRANSMIT, seq_num=1),
        ]
        calc = _make_calc(events)
        self.assertAlmostEqual(calc.average_rtt(), 20.0, places=3)

    def test_min_max_rtt(self):
        """min_rtt ve max_rtt dogru degerler döndürmeli."""
        events = self._make_ack_events([5.0, 15.0, 25.0])
        calc   = _make_calc(events)
        self.assertAlmostEqual(calc.min_rtt(), 5.0,  places=3)
        self.assertAlmostEqual(calc.max_rtt(), 25.0, places=3)


# ---------------------------------------------------------------------------
# Completion Time Testleri
# ---------------------------------------------------------------------------

class TestCompletionTime(unittest.TestCase):
    """completion_time() logger'dan süre hesaplama testleri."""

    def test_from_send_and_fin(self):
        """SEND ve FIN zaman farki dogru hesaplanmali."""
        events = [
            MockLogger.make_entry(EventType.SEND, timestamp=1000.0),
            MockLogger.make_entry(EventType.SEND, timestamp=1001.0),
            MockLogger.make_entry(EventType.FIN,  timestamp=1005.5),
        ]
        calc = _make_calc(events)
        self.assertAlmostEqual(calc.completion_time(), 5.5, places=6)

    def test_from_fin_details_fallback(self):
        """FIN olayinda total_time_s alani varsa oradan alinmali."""
        events = [
            MockLogger.make_entry(EventType.FIN, timestamp=0.0, total_time_s=3.14)
        ]
        calc = _make_calc(events)
        self.assertAlmostEqual(calc.completion_time(), 3.14, places=6)

    def test_no_events_returns_zero(self):
        """Hic olay yokken 0.0 döndürmeli."""
        self.assertEqual(_make_calc([]).completion_time(), 0.0)


# ---------------------------------------------------------------------------
# Sayac Testleri
# ---------------------------------------------------------------------------

class TestCounters(unittest.TestCase):
    """timeout_count, retransmit_count, drop_count, error_count testleri."""

    def _events(self):
        return [
            MockLogger.make_entry(EventType.TIMEOUT,    seq_num=1),
            MockLogger.make_entry(EventType.TIMEOUT,    seq_num=2),
            MockLogger.make_entry(EventType.RETRANSMIT, seq_num=1),
            MockLogger.make_entry(EventType.RETRANSMIT, seq_num=2),
            MockLogger.make_entry(EventType.RETRANSMIT, seq_num=2),
            MockLogger.make_entry(EventType.DROP,       seq_num=3),
            MockLogger.make_entry(EventType.ERROR,      seq_num=4),
        ]

    def test_timeout_count(self):
        self.assertEqual(_make_calc(self._events()).timeout_count(), 2)

    def test_retransmit_count(self):
        self.assertEqual(_make_calc(self._events()).retransmit_count(), 3)

    def test_drop_count(self):
        self.assertEqual(_make_calc(self._events()).drop_count(), 1)

    def test_error_count(self):
        self.assertEqual(_make_calc(self._events()).error_count(), 1)

    def test_all_zero_on_empty(self):
        calc = _make_calc([])
        self.assertEqual(calc.timeout_count(),    0)
        self.assertEqual(calc.retransmit_count(), 0)
        self.assertEqual(calc.drop_count(),       0)
        self.assertEqual(calc.error_count(),      0)


# ---------------------------------------------------------------------------
# Summary Testleri
# ---------------------------------------------------------------------------

class TestSummary(unittest.TestCase):
    """summary() tüm anahtarlarin varligini dogrular."""

    REQUIRED_KEYS = {
        "completion_time_s", "throughput_bps", "goodput_bps",
        "packet_loss_pct", "retransmission_pct",
        "avg_rtt_ms", "min_rtt_ms", "max_rtt_ms",
        "timeout_count", "retransmit_count", "drop_count", "error_count",
        "total_bytes_sent", "file_size_bytes", "total_sent", "total_lost",
    }

    def test_summary_has_all_keys(self):
        """summary() beklenen tüm anahtarlari içermeli."""
        calc = _make_calc([])
        s = calc.summary(
            total_bytes_sent=1000, file_size_bytes=900,
            total_sent=10, total_lost=1,
        )
        for key in self.REQUIRED_KEYS:
            self.assertIn(key, s, f"Eksik anahtar: {key}")

    def test_summary_values_consistent(self):
        """summary() degerlerinin tutarliligi (packet_loss_pct dogrulama)."""
        calc = _make_calc([])
        s = calc.summary(
            total_bytes_sent=5000, file_size_bytes=4096,
            total_sent=5, total_lost=1,
            completion_time_s=1.0,
        )
        self.assertAlmostEqual(s["packet_loss_pct"], 20.0, places=3)
        self.assertAlmostEqual(s["throughput_bps"],  5000.0, places=1)
        self.assertAlmostEqual(s["goodput_bps"],     4096.0, places=1)


# ---------------------------------------------------------------------------
# Giris Noktasi
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)

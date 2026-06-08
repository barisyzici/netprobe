# -*- coding: utf-8 -*-
"""
client.py
=========
NetProbe -- UDP Tabanli Guvenilir Dosya Aktarim Sistemi
Bursa Teknik Universitesi | Bilgisayar Aglari Dersi

Istemci (gönderici) giris noktasi.

Kullanim:
    python client.py --file buyuk_dosya.bin
    python client.py --file foto.jpg --server 192.168.1.5 --port 9001
    python client.py --file test.bin --mode SAW --chunk 512 --window 1
    python client.py --file data.bin --mode GBN --window 8 --timeout 1.0
    python client.py --help

Aktarim tamamlandiginda:
  - Konsola performans raporu basilir
  - reports/ klasörüne JSON rapor dosyasi kaydedilir
"""

import argparse
import json
import os
import socket
import sys
import time

# PYTHONIOENCODING: Windows terminali icin UTF-8 zorla
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Proje kök dizinini sys.path'e ekle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from netprobe.logger   import NetLogger
from netprobe.protocol import ProtocolConfig, ProtocolMode
from netprobe.sender   import Sender
from netprobe.stats    import StatsCalculator

# Simülatör: henüz yazilmadiysa stub olarak kullanilir
try:
    from simulator.network_emulator import NetworkEmulator
    _EMULATOR_AVAILABLE = True
except ImportError:
    _EMULATOR_AVAILABLE = False


# ---------------------------------------------------------------------------
# Renk sabitleri
# ---------------------------------------------------------------------------
class _C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"

if sys.platform == "win32":
    os.system("")


# ---------------------------------------------------------------------------
# Argüman Ayristirici
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """
    Komut satiri argüman ayristiricisini olusturur ve döndürür.

    Returns:
        argparse.ArgumentParser: Yapilandirilmis ayristirici nesnesi.
    """
    p = argparse.ArgumentParser(
        prog="client.py",
        description="NetProbe Istemci -- UDP üzerinde guvenilir dosya gönderimi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ornekler:\n"
            "  python client.py --file resim.png\n"
            "  python client.py --file buyuk.bin --mode GBN --window 8\n"
            "  python client.py --file test.bin --server 10.0.0.5 --port 9001\n"
            "  python client.py --file data.bin --chunk 512 --timeout 1.5\n"
        ),
    )
    p.add_argument(
        "--file", "-f",
        type=str,
        required=True,
        metavar="DOSYA",
        help="(Zorunlu) Gönderilecek dosyanin yolu",
    )
    p.add_argument(
        "--server", "-s",
        type=str,
        default=config.SERVER_IP,
        metavar="IP",
        help=f"Hedef sunucu IP adresi (varsayilan: {config.SERVER_IP})",
    )
    p.add_argument(
        "--port", "-p",
        type=int,
        default=config.SERVER_PORT,
        metavar="PORT",
        help=f"Hedef UDP port numarasi (varsayilan: {config.SERVER_PORT})",
    )
    p.add_argument(
        "--mode", "-m",
        type=str,
        choices=["SAW", "GBN", "SR"],
        default=config.MODE,
        metavar="MOD",
        help="Protokol modu: SAW | GBN | SR  (varsayilan: %(default)s)",
    )
    p.add_argument(
        "--timeout", "-t",
        type=float,
        default=config.TIMEOUT_SEC,
        metavar="SANIYE",
        help=f"ACK bekleme süresi saniye (varsayilan: {config.TIMEOUT_SEC})",
    )
    p.add_argument(
        "--chunk", "-c",
        type=int,
        default=config.CHUNK_SIZE,
        metavar="BYTE",
        help=f"Paket basi veri boyutu byte (varsayilan: {config.CHUNK_SIZE})",
    )
    p.add_argument(
        "--window", "-w",
        type=int,
        default=config.WINDOW_SIZE,
        metavar="N",
        help=f"Sliding window boyutu (varsayilan: {config.WINDOW_SIZE})",
    )
    p.add_argument(
        "--loss", "-l",
        type=float,
        default=0.0,
        metavar="ORAN",
        help="Simülatör paket kayip olasiligi [0.0-1.0] (varsayilan: 0.0)",
    )
    p.add_argument(
        "--delay", "-d",
        type=int,
        default=0,
        metavar="MS",
        help="Simülatör ek gecikme milisaniye (varsayilan: 0)",
    )
    p.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARN"],
        default=config.LOG_LEVEL,
        help="Günlük kayit seviyesi (varsayilan: %(default)s)",
    )
    return p


# ---------------------------------------------------------------------------
# Baslik Yazici
# ---------------------------------------------------------------------------

def print_banner(args: argparse.Namespace, file_size: int) -> None:
    """
    Gönderim baslamadan önce bilgi basligini konsola yazdirir.

    Args:
        args      (argparse.Namespace): Ayristirilan CLI argümanlari.
        file_size (int)               : Gönderilecek dosyanin boyutu (byte).
    """
    def _fmt_bytes(n: int) -> str:
        if n >= 1_048_576:
            return f"{n / 1_048_576:.2f} MB"
        if n >= 1_024:
            return f"{n / 1_024:.2f} KB"
        return f"{n} byte"

    border = "=" * 60
    print(f"\n{_C.BOLD}{_C.MAGENTA}{border}{_C.RESET}")
    print(f"{_C.BOLD}{_C.MAGENTA}  NetProbe Istemci  |  Bursa Teknik Universitesi{_C.RESET}")
    print(f"{_C.BOLD}{_C.MAGENTA}{border}{_C.RESET}")
    print(f"  {_C.BOLD}Hedef sunucu{_C.RESET}: {_C.WHITE}{args.server}:{args.port}{_C.RESET}")
    print(f"  {_C.BOLD}Dosya       {_C.RESET}: {_C.WHITE}{os.path.abspath(args.file)}{_C.RESET}")
    print(f"  {_C.BOLD}Boyut       {_C.RESET}: {_C.WHITE}{_fmt_bytes(file_size)} ({file_size:,} byte){_C.RESET}")
    print(f"  {_C.BOLD}Mod         {_C.RESET}: {_C.GREEN}{args.mode}{_C.RESET}")
    print(f"  {_C.BOLD}Chunk boyutu{_C.RESET}: {_C.WHITE}{args.chunk} byte{_C.RESET}")
    print(f"  {_C.BOLD}Window boyut{_C.RESET}: {_C.WHITE}{args.window}{_C.RESET}")
    print(f"  {_C.BOLD}Timeout     {_C.RESET}: {_C.WHITE}{args.timeout} s{_C.RESET}")
    if args.loss > 0:
        print(f"  {_C.BOLD}Kayip orani {_C.RESET}: {_C.YELLOW}{args.loss*100:.1f}%{_C.RESET}")
    if args.delay > 0:
        print(f"  {_C.BOLD}Gecikme     {_C.RESET}: {_C.YELLOW}{args.delay} ms{_C.RESET}")
    print(f"{_C.BOLD}{_C.MAGENTA}{border}{_C.RESET}")
    print(f"  {_C.CYAN}Gönderim basliyor...{_C.RESET}\n")


# ---------------------------------------------------------------------------
# JSON Rapor Kaydet
# ---------------------------------------------------------------------------

def save_json_report(
    summary: dict,
    filepath: str,
    args: argparse.Namespace,
) -> str:
    """
    Aktarim metriklerini JSON formatinda reports/ klasörüne kaydeder.

    Args:
        summary  (dict)                : StatsCalculator.summary() donusu.
        filepath (str)                 : Gönderilen dosyanin tam yolu.
        args     (argparse.Namespace)  : CLI argümanlari (meta bilgi icin).

    Returns:
        str: Kaydedilen rapor dosyasinin tam yolu.
    """
    os.makedirs(config.REPORT_DIR, exist_ok=True)

    filename   = os.path.basename(filepath)
    name_stem  = os.path.splitext(filename)[0]
    ts_str     = time.strftime("%Y-%m-%d_%H-%M-%S")
    report_name = f"report_{name_stem}_{ts_str}.json"
    report_path = os.path.join(config.REPORT_DIR, report_name)

    report = {
        "meta": {
            "tool":        "NetProbe v1.0.0",
            "university":  "Bursa Teknik Universitesi",
            "timestamp":   ts_str,
            "source_file": os.path.abspath(filepath),
            "server":      f"{args.server}:{args.port}",
            "mode":        args.mode,
            "chunk_size":  args.chunk,
            "window_size": args.window if args.mode != "SAW" else 1,
            "timeout_sec": args.timeout,
            "loss_prob":   args.loss,
            "delay_ms":    args.delay,
        },
        "metrics": summary,
    }

    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    return report_path


# ---------------------------------------------------------------------------
# Ana Fonksiyon
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Istemci ana fonksiyonu.

    Akis:
        1. CLI argümanlarini ayristir.
        2. Dosyanin varligini dogrula.
        3. config.py degerlerini CLI argümanlariyla güncelle.
        4. Klasorleri olustur (received/, reports/, logs/).
        5. UDP soketini ac.
        6. NetLogger ve Sender'i baslat.
        7. Dosyayi gönder.
        8. StatsCalculator raporu ekrana bas.
        9. JSON raporunu reports/ klasörüne kaydet.
        10. Kaynakları temizle.
    """
    parser = build_parser()
    args   = parser.parse_args()

    # ── 1. Dosya kontrolü ───────────────────────────────────────────
    if not os.path.isfile(args.file):
        print(
            f"{_C.RED}[HATA] Dosya bulunamadi: '{args.file}'\n"
            f"       Lütfen gecerli bir dosya yolu belirtin.{_C.RESET}"
        )
        sys.exit(1)

    file_size = os.path.getsize(args.file)
    if file_size == 0:
        print(
            f"{_C.YELLOW}[UYARI] Dosya bos (0 byte): '{args.file}'\n"
            f"        Bos dosya aktarimi desteklenmeyebilir.{_C.RESET}"
        )

    # ── 2. Argüman dogrulamasi ───────────────────────────────────────
    if not (0.0 <= args.loss <= 1.0):
        parser.error(f"--loss 0.0 ile 1.0 arasinda olmalidir: {args.loss}")
    if args.delay < 0:
        parser.error(f"--delay negatif olamaz: {args.delay}")
    if args.chunk <= 0 or args.chunk > 65535:
        parser.error(f"--chunk 1-65535 arasinda olmalidir: {args.chunk}")
    if args.window < 1:
        parser.error(f"--window en az 1 olmalidir: {args.window}")

    # ── 3. config.py'yi CLI argümanlariyla güncelle ─────────────────
    # Böylece ProtocolConfig() bunlari varsayilan olarak okur
    config.MODE         = args.mode
    config.CHUNK_SIZE   = args.chunk
    config.WINDOW_SIZE  = args.window
    config.TIMEOUT_SEC  = args.timeout
    config.SERVER_IP    = args.server
    config.SERVER_PORT  = args.port
    config.LOSS_PROB    = args.loss
    config.DELAY_MS     = args.delay

    # ── 4. Klasörler ────────────────────────────────────────────────
    os.makedirs("received",          exist_ok=True)
    os.makedirs(config.LOG_DIR,      exist_ok=True)
    os.makedirs(config.REPORT_DIR,   exist_ok=True)

    # ── 5. Simülatör uyarisi ────────────────────────────────────────
    if (args.loss > 0 or args.delay > 0) and not _EMULATOR_AVAILABLE:
        print(
            f"{_C.YELLOW}[UYARI] --loss/--delay verildi ancak "
            f"simulator/network_emulator.py bulunamadi. "
            f"Simülasyon uygulanmayacak.{_C.RESET}"
        )

    # ── 6. Baslik ───────────────────────────────────────────────────
    print_banner(args, file_size)

    # ── 7. UDP soketi ───────────────────────────────────────
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as exc:
        print(f"{_C.RED}[HATA] Soket olusturulamadi: {exc}{_C.RESET}")
        sys.exit(1)

    # Emülatör etkinse soketi sar (loss/delay simülasyonu)
    if (args.loss > 0 or args.delay > 0) and _EMULATOR_AVAILABLE:
        # Logger henüz acilmadi, emülatör logu biraz sonra baglanacak
        _raw_emulator = NetworkEmulator(loss_prob=args.loss, delay_ms=args.delay)
        sock = _raw_emulator.wrap_socket(sock)
    else:
        _raw_emulator = None

    # ── 8. Logger + Sender ───────────────────────────────────
    logger = NetLogger(log_level=args.log_level)

    # Emülatör varsa logger'i bagla (drop olaylari kayit edilsin)
    if _raw_emulator is not None:
        _raw_emulator.logger = logger

    cfg = ProtocolConfig(
        chunk_size  = args.chunk,
        window_size = args.window,
        timeout_sec = args.timeout,
        mode        = ProtocolMode(args.mode),
    )

    sender = Sender(
        sock        = sock,
        server_addr = (args.server, args.port),
        logger      = logger,
        cfg         = cfg,
    )

    # ── 9. Gönderim ─────────────────────────────────────────────────
    try:
        t_wall_start = time.perf_counter()
        send_stats   = sender.send_file(args.file)
        t_wall_end   = time.perf_counter()
        wall_time    = t_wall_end - t_wall_start
        # Windows'ta cok hizli transferlerde wall_time = 0 olabilir;
        # sender'in kendi olcumunü geri donus olarak kullan
        if wall_time <= 0:
            wall_time = send_stats.get("completion_time_s", 1e-6) or 1e-6

    except FileNotFoundError:
        print(f"{_C.RED}[HATA] Gönderim sirasinda dosya kayboldu: {args.file}{_C.RESET}")
        sock.close()
        logger.close()
        sys.exit(1)

    except KeyboardInterrupt:
        print(f"\n{_C.YELLOW}[UYARI] Gönderim kullanici tarafindan iptal edildi.{_C.RESET}")
        sock.close()
        logger.close()
        sys.exit(0)

    except Exception as exc:
        print(f"{_C.RED}[HATA] Beklenmeyen hata: {exc}{_C.RESET}")
        sock.close()
        logger.close()
        sys.exit(1)

    finally:
        sock.close()

    # ── 10. Rapor ───────────────────────────────────────────────────
    calc = StatsCalculator(logger)

    total_retransmit = calc.retransmit_count()
    total_lost       = send_stats.get("total_lost", 0)
    total_sent       = send_stats.get("total_chunks", 0)
    total_bytes_sent = send_stats.get("total_bytes_sent", 0)

    summary = calc.print_report(
        total_bytes_sent  = total_bytes_sent,
        file_size_bytes   = file_size,
        total_sent        = total_sent,
        total_lost        = total_lost,
        total_retransmit  = total_retransmit,
        completion_time_s = wall_time,
    )

    # ── 11. JSON rapor dosyasini kaydet ─────────────────────────────
    try:
        report_path = save_json_report(summary, args.file, args)
        print(
            f"{_C.BOLD}{_C.WHITE}Rapor kaydedildi: "
            f"{_C.CYAN}{report_path}{_C.RESET}\n"
        )
    except IOError as exc:
        print(f"{_C.YELLOW}[UYARI] JSON rapor kaydedilemedi: {exc}{_C.RESET}")

    # ── 12. Temizlik ────────────────────────────────────────────────
    logger.close()


# ---------------------------------------------------------------------------
# Giris Noktasi
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()

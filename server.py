# -*- coding: utf-8 -*-
"""
server.py
=========
NetProbe -- UDP Tabanli Guvenilir Dosya Aktarim Sistemi
Bursa Teknik Universitesi | Bilgisayar Aglari Dersi

Sunucu (alici) giriş noktasi.

Kullanim:
    python server.py
    python server.py --port 9001 --mode SAW --output ./alinan/
    python server.py --port 9000 --loss 0.1 --delay 50
    python server.py --help

Her aktarim tamamlandiginda performans raporu ekrana basilir ve
sunucu bir sonraki aktarimi beklemeye devam eder.
Ctrl+C ile guvenli cikis yapilir.
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
from netprobe.receiver import Receiver
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
        prog="server.py",
        description="NetProbe Sunucu -- UDP üzerinde guvenilir dosya alimi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ornekler:\n"
            "  python server.py\n"
            "  python server.py --port 9001 --mode SAW\n"
            "  python server.py --loss 0.1 --delay 50\n"
        ),
    )
    p.add_argument(
        "--port", "-p",
        type=int,
        default=config.SERVER_PORT,
        metavar="PORT",
        help=f"Dinlenecek UDP port numarasi (varsayilan: {config.SERVER_PORT})",
    )
    p.add_argument(
        "--output", "-o",
        type=str,
        default="./received/",
        metavar="DIZIN",
        help="Alinan dosyalarin kaydedilecegi klasor (varsayilan: ./received/)",
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
        help="Simülatör ek gecikme (milisaniye, varsayilan: 0)",
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

def print_banner(args: argparse.Namespace) -> None:
    """
    Sunucu basladiginda bilgi basligini konsola yazdirir.

    Args:
        args (argparse.Namespace): Ayristirilan komut satiri argümanlari.
    """
    border = "=" * 58
    print(f"\n{_C.BOLD}{_C.CYAN}{border}{_C.RESET}")
    print(f"{_C.BOLD}{_C.CYAN}  NetProbe Sunucu  |  Bursa Teknik Universitesi{_C.RESET}")
    print(f"{_C.BOLD}{_C.CYAN}{border}{_C.RESET}")
    print(f"  {_C.BOLD}Port       {_C.RESET}: {_C.WHITE}{args.port}{_C.RESET}")
    print(f"  {_C.BOLD}Mod        {_C.RESET}: {_C.GREEN}{args.mode}{_C.RESET}")
    print(f"  {_C.BOLD}Cikti klas.{_C.RESET}: {_C.WHITE}{os.path.abspath(args.output)}{_C.RESET}")
    if args.loss > 0:
        print(f"  {_C.BOLD}Kayip orani{_C.RESET}: {_C.YELLOW}{args.loss*100:.1f}%{_C.RESET}")
    if args.delay > 0:
        print(f"  {_C.BOLD}Gecikme    {_C.RESET}: {_C.YELLOW}{args.delay} ms{_C.RESET}")
    print(f"{_C.BOLD}{_C.CYAN}{border}{_C.RESET}")
    print(f"  {_C.GREEN}Baglanti bekleniyor... (Ctrl+C ile dur){_C.RESET}\n")


# ---------------------------------------------------------------------------
# Ana Fonksiyon
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Sunucu ana döngüsü.

    1. CLI argümanlarini ayristirir.
    2. Gerekli klasorleri olusturur.
    3. UDP soketini acar ve bind eder.
    4. Her aktarim icin bir Receiver + Logger olusturur.
    5. Aktarim tamamlaninca StatsCalculator ile rapor basar.
    6. Sonraki aktarimi beklemek icin döngüye döner.
    7. Ctrl+C aldiginda temiz cikis yapar.
    """
    parser = build_parser()
    args   = parser.parse_args()

    # Argüman dogrulamasi
    if not (0.0 <= args.loss <= 1.0):
        parser.error(f"--loss 0.0 ile 1.0 arasinda olmalidir, alindi: {args.loss}")
    if args.delay < 0:
        parser.error(f"--delay negatif olamaz, alindi: {args.delay}")

    # Klasorler
    os.makedirs(args.output, exist_ok=True)
    os.makedirs(config.LOG_DIR, exist_ok=True)
    os.makedirs(config.REPORT_DIR, exist_ok=True)

    # Simülatör uyarisi
    emulator = None
    if (args.loss > 0 or args.delay > 0):
        if _EMULATOR_AVAILABLE:
            emulator = NetworkEmulator(loss_prob=args.loss, delay_ms=args.delay)
        else:
            print(
                f"{_C.YELLOW}[UYARI] --loss/--delay verildi ancak "
                f"simulator/network_emulator.py bulunamadi. "
                f"Simülasyon uygulanmayacak.{_C.RESET}"
            )

    # UDP soketi
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", args.port))
    except OSError as exc:
        print(f"{_C.RED}[HATA] Soket baglantisi basarisiz: {exc}{_C.RESET}")
        sys.exit(1)

    # Protokol konfigürasyonu
    cfg = ProtocolConfig(
        mode=ProtocolMode(args.mode),
    )

    print_banner(args)

    transfer_count = 0

    try:
        while True:
            transfer_count += 1
            ts_str = time.strftime("%Y-%m-%d_%H-%M-%S")

            # Her aktarim icin yeni logger ve cikti dosyasi
            logger      = NetLogger(log_level=args.log_level)
            output_path = os.path.join(
                args.output, f"received_{ts_str}_{transfer_count}.bin"
            )

            print(
                f"{_C.BOLD}{_C.WHITE}[Aktarim #{transfer_count}]{_C.RESET} "
                f"Bekleniyor... -> {output_path}"
            )

            try:
                receiver = Receiver(sock, logger, cfg)
                result   = receiver.receive_file(output_path)
            except Exception as exc:
                print(f"{_C.RED}[HATA] Aktarim hatasi: {exc}{_C.RESET}")
                logger.close()
                continue

            # Rapor
            calc = StatsCalculator(logger)

            received = result.get("received_packets", 0)
            dropped  = result.get("dropped_packets",  0)
            fsize    = result.get("file_size_bytes",  0)

            print(
                f"\n{_C.GREEN}[Aktarim #{transfer_count} Tamamlandi]{_C.RESET}  "
                f"{received} paket alindi, {dropped} dusuruldu, "
                f"{fsize:,} byte yazildi"
            )
            if result.get("integrity_ok") is not None:
                ok_str = (
                    f"{_C.GREEN}GECTI{_C.RESET}"
                    if result["integrity_ok"]
                    else f"{_C.RED}BASARISIZ{_C.RESET}"
                )
                print(f"  MD5 Bütünlük Kontrolü: {ok_str}")

            # StatsCalculator summary (alici tarafinda bytes bilinmez tam)
            # Temel istatistikleri göster
            avg_rtt = calc.average_rtt()
            if avg_rtt > 0:
                print(f"  Ortalama RTT : {avg_rtt:.3f} ms")

            logger.close()

            # Sonraki aktarim icin hazir mesaji
            print(
                f"\n{_C.CYAN}Sonraki aktarim bekleniyor... "
                f"(Ctrl+C ile cikis){_C.RESET}\n"
            )

    except KeyboardInterrupt:
        print(
            f"\n{_C.BOLD}{_C.MAGENTA}"
            f"[NetProbe] Sunucu durduruluyor... "
            f"Toplam {transfer_count} aktarim yapildi."
            f"{_C.RESET}"
        )
    finally:
        sock.close()
        print(f"{_C.CYAN}[NetProbe] Soket kapatildi. Güle güle!{_C.RESET}\n")


# ---------------------------------------------------------------------------
# Giris Noktasi
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()

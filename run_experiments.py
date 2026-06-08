# -*- coding: utf-8 -*-
"""
run_experiments.py
==================
NetProbe -- Otomatik Deney Kosucu
Bursa Teknik Universitesi | Bilgisayar Aglari Dersi

4 senaryoyu otomatik kosturur, her senaryoyu 3 kez tekrarlar,
ortalama alarak reports/experiments.json dosyasina yazar.

Calistirmak icin:
    python run_experiments.py

Cikti:
    reports/experiments.json  -- ham deney sonuclari
    reports/               -- her deneme icin ayri JSON raporu
"""

import glob
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

# PYTHONIOENCODING
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.platform == "win32":
    os.system("")

ROOT       = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(ROOT, "reports")
RECV_DIR   = os.path.join(ROOT, "received")
LOG_DIR    = os.path.join(ROOT, "logs")
PYTHON     = sys.executable

# Deney sabitleri
REPEATS     = 3       # Her parametre degeri kac kez tekrarlanir
FILE_500KB  = 500 * 1024   # Senaryo 1-3 icin sabit dosya boyutu
BASE_PORT   = 20100        # Deney portlari buradan baslar
TIMEOUT_EXP = 60           # Her deney icin maksimum bekleme süresi (s)

# Renk sabitleri
class _C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"


# ---------------------------------------------------------------------------
# Yardimci Fonksiyonlar
# ---------------------------------------------------------------------------

def wait_for_server_ready(
    server_proc: "subprocess.Popen",
    host: str,
    port: int,
    timeout: float = 5.0,
) -> bool:
    """
    Sunucu UDP portuna bind olana kadar bekler.

    Windows'ta UDP SO_REUSEADDR ayni porta birden fazla bind'a izin
    verdigi icin port-bind testi guvenilir degildir. Bu nedenle:
      1. Server process'in baslamasi icin kisa bir sure beklenir.
      2. Process hala hayatta ise hazir kabul edilir.
      3. Process erken olmusse False doneriz.

    Args:
        server_proc (subprocess.Popen): Calisan sunucu sureci.
        host        (str)  : Sunucu adresi (kullanilmiyor, uyumluluk icin).
        port        (int)  : Beklenen UDP port (kullanilmiyor, uyumluluk icin).
        timeout     (float): Maksimum bekleme suresi (saniye).

    Returns:
        bool: Sunucu hazir ise True, erken kapandiysa False.
    """
    deadline = time.monotonic() + timeout
    # Server'a bind etmesi icin yeterli sure ver (Python baslatma + import + bind)
    time.sleep(0.5)

    while time.monotonic() < deadline:
        rc = server_proc.poll()
        if rc is not None:
            # Server erken kapandi (port mesgul ya da baska hata)
            return False
        return True

    return False


def make_test_file(size_bytes: int) -> str:
    """
    Belirtilen boyutta rastgele icerikli gecici bir test dosyasi olusturur.

    Args:
        size_bytes (int): Dosya boyutu (byte).

    Returns:
        str: Olusturulan gecici dosyanin tam yolu.
    """
    fd, path = tempfile.mkstemp(suffix=".bin", dir=ROOT)
    os.write(fd, os.urandom(size_bytes))
    os.close(fd)
    return path


def find_latest_report(before_files: set) -> Optional[Dict]:
    """
    Deney öncesindeki dosya listesiyle sonrasini karsilastirarak
    en yeni JSON raporu bulur ve icerigini döndürür.

    Args:
        before_files (set): Deney baslama öncesi reports/ dosya seti.

    Returns:
        Optional[Dict]: JSON rapor icerik, bulunamazsa None.
    """
    after_files = set(os.listdir(REPORT_DIR))
    new_files   = [
        f for f in (after_files - before_files) if f.endswith(".json")
    ]
    if not new_files:
        return None

    latest = max(
        new_files,
        key=lambda f: os.path.getmtime(os.path.join(REPORT_DIR, f)),
    )
    with open(os.path.join(REPORT_DIR, latest), encoding="utf-8") as fh:
        return json.load(fh)


def run_one_trial(
    file_path:         str,
    port:              int,
    client_extra_args: List[str],
    server_mode:       str = "GBN",
) -> Optional[Dict[str, Any]]:
    """
    Tek bir deney tekrarini kosturur: server baslatir, client calistirir,
    JSON raporu okur, server'i durdurur.

    Args:
        file_path         (str)      : Gönderilecek test dosyasinin yolu.
        port              (int)      : Kullanilacak UDP port.
        client_extra_args (List[str]): client.py'ye iletilecek ek argümanlar.
        server_mode       (str)      : Sunucu protokol modu.

    Returns:
        Optional[Dict]: 'metrics' alt anahtarini iceren rapor sozlügü, ya da None.
    """
    # Sunucuyu arka planda baslat
    server_proc = subprocess.Popen(
        [PYTHON, "server.py",
         "--port", str(port),
         "--mode", server_mode,
         "--output", RECV_DIR,
         "--log-level", "WARN"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=ROOT,
    )

    # Sunucu hazir olana kadar bekle
    if not wait_for_server_ready(server_proc, "127.0.0.1", port, timeout=5.0):
        server_proc.terminate()
        return None

    # Deney öncesi rapor listesi
    os.makedirs(REPORT_DIR, exist_ok=True)
    before = set(os.listdir(REPORT_DIR))

    # Client'i calistir
    try:
        client_proc = subprocess.run(
            [PYTHON, "client.py",
             "--file",      file_path,
             "--port",      str(port),
             "--mode",      server_mode,
             "--log-level", "WARN"]
            + client_extra_args,
            capture_output=True,
            cwd=ROOT,
            timeout=TIMEOUT_EXP,
        )
    except subprocess.TimeoutExpired:
        server_proc.terminate()
        return None

    # FIN-ACK islemesi icin biraz bekle
    time.sleep(0.3)
    server_proc.terminate()
    try:
        server_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server_proc.kill()

    if client_proc.returncode != 0:
        return None

    return find_latest_report(before)


def average_metrics(results: List[Dict]) -> Dict[str, float]:
    """
    Birden fazla deneme sonucunun ortalamalarini hesaplar.

    Args:
        results (List[Dict]): Her biri 'metrics' anahtari iceren rapor listesi.

    Returns:
        Dict[str, float]: Ortalama metrik degerleri.
    """
    metrics_list = [r["metrics"] for r in results if r and "metrics" in r]
    if not metrics_list:
        return {}

    keys = metrics_list[0].keys()
    return {
        k: round(sum(m[k] for m in metrics_list if k in m) / len(metrics_list), 4)
        for k in keys
        if isinstance(metrics_list[0].get(k), (int, float))
    }


def print_progress(scenario: str, param_name: str, value: Any, rep: int) -> None:
    """Deney ilerlemesini konsolda gösterir."""
    print(
        f"  {_C.CYAN}[{scenario}]{_C.RESET} "
        f"{param_name}={value}  "
        f"deneme={rep}/{REPEATS}",
        end="\r",
    )


# ---------------------------------------------------------------------------
# Senaryolar
# ---------------------------------------------------------------------------

def scenario_1_chunk_size(
    file_path: str,
    port_base: int,
) -> Dict:
    """
    Senaryo 1: Chunk boyutunun throughput'a etkisi.

    Sabit 500KB dosya, kayip yok.
    Degisen: chunk_size = [256, 512, 1024, 2048, 4096]

    Args:
        file_path (str): Test dosyasi yolu.
        port_base (int): Baslangic port numarasi.

    Returns:
        Dict: Her chunk_size degeri icin ortalama metrikler.
    """
    chunk_sizes = [256, 512, 1024, 2048, 4096]
    results     = {}
    port        = port_base

    print(f"\n{_C.BOLD}{_C.MAGENTA}Senaryo 1: Chunk Boyutu vs Throughput{_C.RESET}")

    for cs in chunk_sizes:
        trials = []
        for rep in range(1, REPEATS + 1):
            print_progress("S1", "chunk", cs, rep)
            r = run_one_trial(
                file_path,
                port,
                ["--chunk", str(cs), "--window", "4"],
            )
            if r:
                trials.append(r)
            port += 1
            time.sleep(0.2)

        avg = average_metrics(trials)
        results[str(cs)] = avg
        tp_kbs = avg.get("throughput_bps", 0) / 1000
        print(
            f"\r  {_C.GREEN}[S1]{_C.RESET} "
            f"chunk={cs:<5}  throughput={tp_kbs:.1f} KB/s  "
            f"({len(trials)}/{REPEATS} basarili)"
        )

    return results


def scenario_2_timeout(
    file_path: str,
    port_base: int,
) -> Dict:
    """
    Senaryo 2: Timeout süresinin %5 kayip altinda etkisi.

    Sabit 500KB dosya, %5 kayip.
    Degisen: timeout = [0.2, 0.5, 1.0, 2.0]

    Args:
        file_path (str): Test dosyasi yolu.
        port_base (int): Baslangic port numarasi.

    Returns:
        Dict: Her timeout degeri icin ortalama metrikler.
    """
    timeouts = [0.2, 0.5, 1.0, 2.0]
    results  = {}
    port     = port_base

    print(f"\n{_C.BOLD}{_C.MAGENTA}Senaryo 2: Timeout vs Retransmission (%5 kayip){_C.RESET}")

    for t in timeouts:
        trials = []
        for rep in range(1, REPEATS + 1):
            print_progress("S2", "timeout", t, rep)
            r = run_one_trial(
                file_path,
                port,
                ["--timeout", str(t), "--loss", "0.05", "--window", "4"],
            )
            if r:
                trials.append(r)
            port += 1
            time.sleep(0.2)

        avg = average_metrics(trials)
        results[str(t)] = avg
        rt_pct = avg.get("retransmission_pct", 0)
        print(
            f"\r  {_C.GREEN}[S2]{_C.RESET} "
            f"timeout={t:<5}  retransmit={rt_pct:.1f}%  "
            f"({len(trials)}/{REPEATS} basarili)"
        )

    return results


def scenario_3_loss_rate(
    file_path: str,
    port_base: int,
) -> Dict:
    """
    Senaryo 3: Kayip oraninin goodput'a etkisi.

    Sabit 500KB dosya.
    Degisen: loss_rate = [0, 0.05, 0.1, 0.2, 0.3]

    Args:
        file_path (str): Test dosyasi yolu.
        port_base (int): Baslangic port numarasi.

    Returns:
        Dict: Her loss_rate degeri icin ortalama metrikler.
    """
    loss_rates = [0.0, 0.05, 0.1, 0.2, 0.3]
    results    = {}
    port       = port_base

    print(f"\n{_C.BOLD}{_C.MAGENTA}Senaryo 3: Kayip Orani vs Goodput{_C.RESET}")

    for lr in loss_rates:
        trials = []
        for rep in range(1, REPEATS + 1):
            print_progress("S3", "loss", lr, rep)
            r = run_one_trial(
                file_path,
                port,
                ["--loss", str(lr), "--window", "4", "--timeout", "0.5"],
            )
            if r:
                trials.append(r)
            port += 1
            time.sleep(0.3)

        avg = average_metrics(trials)
        results[str(lr)] = avg
        gp_kbs = avg.get("goodput_bps", 0) / 1000
        print(
            f"\r  {_C.GREEN}[S3]{_C.RESET} "
            f"loss={lr:<5}  goodput={gp_kbs:.1f} KB/s  "
            f"({len(trials)}/{REPEATS} basarili)"
        )

    return results


def scenario_4_file_size(
    port_base: int,
) -> Dict:
    """
    Senaryo 4: Dosya boyutunun tamamlanma süresine etkisi.

    Kayip yok. Test dosyalari otomatik üretilir.
    Boyutlar: [10KB, 50KB, 200KB, 500KB, 1MB]

    Args:
        port_base (int): Baslangic port numarasi.

    Returns:
        Dict: Her dosya boyutu icin ortalama metrikler.
    """
    file_sizes = [
        (10   * 1024, "10KB"),
        (50   * 1024, "50KB"),
        (200  * 1024, "200KB"),
        (500  * 1024, "500KB"),
        (1024 * 1024, "1MB"),
    ]
    results = {}
    port    = port_base
    temp_files = []

    print(f"\n{_C.BOLD}{_C.MAGENTA}Senaryo 4: Dosya Boyutu vs Tamamlanma Süresi{_C.RESET}")

    try:
        for size_bytes, label in file_sizes:
            fpath = make_test_file(size_bytes)
            temp_files.append(fpath)

            trials = []
            for rep in range(1, REPEATS + 1):
                print_progress("S4", "size", label, rep)
                r = run_one_trial(
                    fpath,
                    port,
                    ["--window", "4", "--chunk", "1024"],
                )
                if r:
                    trials.append(r)
                port += 1
                time.sleep(0.2)

            avg = average_metrics(trials)
            results[label] = avg
            ct_s = avg.get("completion_time_s", 0)
            print(
                f"\r  {_C.GREEN}[S4]{_C.RESET} "
                f"size={label:<6}  süre={ct_s:.3f}s  "
                f"({len(trials)}/{REPEATS} basarili)"
            )
    finally:
        for f in temp_files:
            try:
                os.unlink(f)
            except OSError:
                pass

    return results


# ---------------------------------------------------------------------------
# Ana Fonksiyon
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Tüm deneyleri sirali olarak kosturur ve sonuclari JSON'a yazar.

    Toplam deney sayisi:
        S1: 5 chunk x 3 = 15
        S2: 4 timeout x 3 = 12
        S3: 5 loss x 3 = 15
        S4: 5 boyut x 3 = 15
        Toplam: 57 deney
    """
    os.makedirs(REPORT_DIR, exist_ok=True)
    os.makedirs(RECV_DIR,   exist_ok=True)
    os.makedirs(LOG_DIR,    exist_ok=True)

    border = "=" * 60
    print(f"\n{_C.BOLD}{_C.CYAN}{border}{_C.RESET}")
    print(f"{_C.BOLD}{_C.CYAN}  NetProbe Deney Kosucu -- BTU Bilgisayar Aglari{_C.RESET}")
    print(f"{_C.BOLD}{_C.CYAN}{border}{_C.RESET}")
    print(f"  Tekrar sayisi  : {REPEATS}")
    print(f"  Deney dosyasi  : {FILE_500KB // 1024} KB")
    print(f"  Deney zaman asm: {TIMEOUT_EXP} s")
    print(f"  Baslangic portu: {BASE_PORT}")
    print()

    # Senaryo 1-3 icin paylasilmis test dosyasi
    print(f"{_C.WHITE}500 KB test dosyasi olusturuluyor...{_C.RESET}")
    shared_file = make_test_file(FILE_500KB)

    t_total_start = time.monotonic()

    try:
        all_results = {
            "meta": {
                "tool":      "NetProbe v1.0.0",
                "university": "Bursa Teknik Universitesi",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "repeats":   REPEATS,
            },
            "scenario_1_chunk_size": scenario_1_chunk_size(shared_file, BASE_PORT),
            "scenario_2_timeout":    scenario_2_timeout(shared_file, BASE_PORT + 50),
            "scenario_3_loss_rate":  scenario_3_loss_rate(shared_file, BASE_PORT + 100),
            "scenario_4_file_size":  scenario_4_file_size(BASE_PORT + 150),
        }
    finally:
        try:
            os.unlink(shared_file)
        except OSError:
            pass

    elapsed = time.monotonic() - t_total_start

    # Sonuclari kaydet
    out_path = os.path.join(REPORT_DIR, "experiments.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(all_results, fh, ensure_ascii=False, indent=2)

    print(f"\n{_C.BOLD}{_C.GREEN}")
    print(f"  Tüm deneyler tamamlandi!  ({elapsed:.1f} s)")
    print(f"  Sonuclar: {out_path}")
    print(f"{_C.RESET}")


# ---------------------------------------------------------------------------
# Giris Noktasi
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()

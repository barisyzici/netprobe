# -*- coding: utf-8 -*-
"""
analyze.py
==========
NetProbe -- Deney Sonuçlari Analiz ve Grafik Üretici
Bursa Teknik Universitesi | Bilgisayar Aglari Dersi

reports/experiments.json dosyasini okuyarak 4 grafik üretir
ve reports/ klasörüne PNG olarak kaydeder.

Calistirmak icin:
    python analyze.py
    python analyze.py --input reports/experiments.json
    python analyze.py --help

Cikti dosyalari:
    reports/throughput_vs_chunksize.png
    reports/retransmission_vs_timeout.png
    reports/goodput_vs_lossrate.png
    reports/completion_vs_filesize.png
"""

import argparse
import json
import os
import sys

# matplotlib kontrolü
try:
    import matplotlib
    matplotlib.use("Agg")   # Ekransiz (headless) arka plan
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
    _MPL_OK = True
except ImportError:
    _MPL_OK = False

# PYTHONIOENCODING
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.platform == "win32":
    os.system("")

ROOT       = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(ROOT, "reports")


# ---------------------------------------------------------------------------
# Renk ve Stil Sabitleri
# ---------------------------------------------------------------------------

STYLE = {
    "figure.facecolor":   "#1a1a2e",
    "axes.facecolor":     "#16213e",
    "axes.edgecolor":     "#4a4a8a",
    "axes.labelcolor":    "#e0e0e0",
    "axes.titlecolor":    "#ffffff",
    "xtick.color":        "#c0c0c0",
    "ytick.color":        "#c0c0c0",
    "grid.color":         "#2a2a5a",
    "grid.linestyle":     "--",
    "grid.alpha":         0.6,
    "text.color":         "#e0e0e0",
    "legend.facecolor":   "#1e1e3e",
    "legend.edgecolor":   "#4a4a8a",
    "figure.figsize":     (9, 5.5),
    "figure.dpi":         120,
    "lines.linewidth":    2.2,
    "lines.markersize":   8,
}

COLORS = {
    "primary":   "#00d4ff",   # Cyan — ana çizgi
    "secondary": "#ff6b6b",   # Kirmizi -- ikincil
    "accent":    "#ffd93d",   # Sari -- vurgu
    "fill":      "#00d4ff33", # Seffaf dolgu
}

CLASS_C = "\033[96m"
RESET   = "\033[0m"
BOLD    = "\033[1m"
GREEN   = "\033[92m"
RED     = "\033[91m"


# ---------------------------------------------------------------------------
# Yardimci Fonksiyonlar
# ---------------------------------------------------------------------------

def _apply_style() -> None:
    """Dark theme stil ayarlarini matplotlib'e uygular."""
    for k, v in STYLE.items():
        try:
            plt.rcParams[k] = v
        except KeyError:
            pass


def _add_watermark(ax: "plt.Axes") -> None:
    """Grafige BTU filigrani ekler."""
    ax.text(
        0.99, 0.02,
        "NetProbe | BTU Bilgisayar Aglari",
        transform=ax.transAxes,
        fontsize=7, color="#4a4a8a",
        ha="right", va="bottom", style="italic",
    )


def _save(fig: "plt.Figure", filename: str) -> str:
    """Grafigi PNG olarak kaydeder ve yolunu döndürür."""
    path = os.path.join(REPORT_DIR, filename)
    fig.savefig(path, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    return path


def _extract_xy(
    scenario: dict,
    y_key: str,
    scale: float = 1.0,
) -> tuple:
    """
    Senaryo sözlügünden x (parametre) ve y (metrik) degerlerini cikarir.

    Args:
        scenario (dict)  : Senaryo sonuclari (key=param str, value=metrikler).
        y_key    (str)   : Cikarmak istenen metrik anahtari.
        scale    (float) : Y degerine uygulanacak olcekleme carpani.

    Returns:
        Tuple[List, List]: (x_values, y_values)
    """
    x_vals, y_vals = [], []
    for k, metrics in scenario.items():
        if isinstance(metrics, dict) and y_key in metrics:
            try:
                x_vals.append(float(k))
                y_vals.append(float(metrics[y_key]) * scale)
            except (ValueError, TypeError):
                pass
    paired = sorted(zip(x_vals, y_vals))
    if not paired:
        return [], []
    x, y = zip(*paired)
    return list(x), list(y)


# ---------------------------------------------------------------------------
# Grafik 1: Throughput vs Chunk Size
# ---------------------------------------------------------------------------

def plot_throughput_vs_chunksize(data: dict) -> str:
    """
    Senaryo 1: Chunk boyutu ile throughput iliskisini çizer.

    X ekseni: Chunk boyutu (byte, log olcegi)
    Y ekseni: Ortalama Throughput (KB/s)

    Args:
        data (dict): experiments.json icerik sozlügü.

    Returns:
        str: Kaydedilen PNG dosyasinin yolu.
    """
    scenario = data.get("scenario_1_chunk_size", {})
    x, y     = _extract_xy(scenario, "throughput_bps", scale=1 / 1000)

    fig, ax = plt.subplots()
    _apply_style()
    fig.patch.set_facecolor(STYLE["figure.facecolor"])
    ax.set_facecolor(STYLE["axes.facecolor"])

    if x and y:
        ax.plot(x, y, "o-", color=COLORS["primary"], label="Throughput")
        ax.fill_between(x, y, alpha=0.15, color=COLORS["primary"])
        for xi, yi in zip(x, y):
            ax.annotate(
                f"{yi:.0f}",
                (xi, yi), textcoords="offset points",
                xytext=(0, 10), ha="center", fontsize=9, color=COLORS["primary"],
            )
    else:
        ax.text(0.5, 0.5, "Veri bulunamadi",
                ha="center", va="center", transform=ax.transAxes,
                color="#888888", fontsize=14)

    ax.set_xscale("log", base=2)
    ax.set_xlabel("Chunk Boyutu (byte)", fontsize=11)
    ax.set_ylabel("Throughput (KB/s)", fontsize=11)
    ax.set_title("Chunk Boyutu vs Throughput\n(500 KB dosya, kayip yok, GBN w=4)",
                 fontsize=12, fontweight="bold")
    ax.grid(True, linestyle=STYLE.get("grid.linestyle", "--"),
            alpha=STYLE.get("grid.alpha", 0.6),
            color=STYLE.get("grid.color", "#2a2a5a"))
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: f"{int(v)}"
    ))
    ax.legend(loc="upper left")
    _add_watermark(ax)
    fig.tight_layout()

    return _save(fig, "throughput_vs_chunksize.png")


# ---------------------------------------------------------------------------
# Grafik 2: Retransmission vs Timeout
# ---------------------------------------------------------------------------

def plot_retransmission_vs_timeout(data: dict) -> str:
    """
    Senaryo 2: Timeout süresi ile yeniden gönderim orani iliskisini çizer.

    X ekseni: Timeout süresi (s)
    Y ekseni: Yeniden Gönderim Orani (%)

    Args:
        data (dict): experiments.json icerik sozlügü.

    Returns:
        str: Kaydedilen PNG dosyasinin yolu.
    """
    scenario = data.get("scenario_2_timeout", {})
    x, y     = _extract_xy(scenario, "retransmission_pct")

    fig, ax = plt.subplots()
    _apply_style()
    fig.patch.set_facecolor(STYLE["figure.facecolor"])
    ax.set_facecolor(STYLE["axes.facecolor"])

    if x and y:
        ax.plot(x, y, "s-", color=COLORS["secondary"], label="Retransmission %")
        ax.fill_between(x, y, alpha=0.15, color=COLORS["secondary"])
        for xi, yi in zip(x, y):
            ax.annotate(
                f"{yi:.1f}%",
                (xi, yi), textcoords="offset points",
                xytext=(0, 10), ha="center", fontsize=9, color=COLORS["secondary"],
            )
    else:
        ax.text(0.5, 0.5, "Veri bulunamadi",
                ha="center", va="center", transform=ax.transAxes,
                color="#888888", fontsize=14)

    ax.set_xlabel("Timeout Süresi (s)", fontsize=11)
    ax.set_ylabel("Yeniden Gönderim Orani (%)", fontsize=11)
    ax.set_title("Timeout Süresi vs Yeniden Gönderim Orani\n(%5 kayip, 500 KB dosya, GBN w=4)",
                 fontsize=12, fontweight="bold")
    ax.grid(True)
    ax.legend(loc="upper right")
    _add_watermark(ax)
    fig.tight_layout()

    return _save(fig, "retransmission_vs_timeout.png")


# ---------------------------------------------------------------------------
# Grafik 3: Goodput vs Loss Rate
# ---------------------------------------------------------------------------

def plot_goodput_vs_lossrate(data: dict) -> str:
    """
    Senaryo 3: Kayip orani ile goodput iliskisini çizer.

    X ekseni: Kayip Orani (%)
    Y ekseni: Goodput (KB/s)

    Args:
        data (dict): experiments.json icerik sozlügü.

    Returns:
        str: Kaydedilen PNG dosyasinin yolu.
    """
    scenario = data.get("scenario_3_loss_rate", {})
    x_raw, y = _extract_xy(scenario, "goodput_bps", scale=1 / 1000)
    x        = [xi * 100 for xi in x_raw]   # Oranı yüzdeye cevir

    fig, ax = plt.subplots()
    _apply_style()
    fig.patch.set_facecolor(STYLE["figure.facecolor"])
    ax.set_facecolor(STYLE["axes.facecolor"])

    if x and y:
        ax.plot(x, y, "^-", color=COLORS["accent"], label="Goodput")
        ax.fill_between(x, y, alpha=0.15, color=COLORS["accent"])
        for xi, yi in zip(x, y):
            ax.annotate(
                f"{yi:.0f}",
                (xi, yi), textcoords="offset points",
                xytext=(0, 10), ha="center", fontsize=9, color=COLORS["accent"],
            )
    else:
        ax.text(0.5, 0.5, "Veri bulunamadi",
                ha="center", va="center", transform=ax.transAxes,
                color="#888888", fontsize=14)

    ax.set_xlabel("Kayip Orani (%)", fontsize=11)
    ax.set_ylabel("Goodput (KB/s)", fontsize=11)
    ax.set_title("Kayip Orani vs Goodput\n(500 KB dosya, GBN w=4, timeout=0.5s)",
                 fontsize=12, fontweight="bold")
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.grid(True)
    ax.legend(loc="upper right")
    _add_watermark(ax)
    fig.tight_layout()

    return _save(fig, "goodput_vs_lossrate.png")


# ---------------------------------------------------------------------------
# Grafik 4: Completion Time vs File Size
# ---------------------------------------------------------------------------

def plot_completion_vs_filesize(data: dict) -> str:
    """
    Senaryo 4: Dosya boyutu ile tamamlanma süresi iliskisini çizer.

    X ekseni: Dosya Boyutu (KB, log olcegi)
    Y ekseni: Ortalama Tamamlanma Süresi (s)

    Args:
        data (dict): experiments.json icerik sozlügü.

    Returns:
        str: Kaydedilen PNG dosyasinin yolu.
    """
    scenario  = data.get("scenario_4_file_size", {})
    SIZE_MAP  = {"10KB": 10, "50KB": 50, "200KB": 200, "500KB": 500, "1MB": 1024}

    x_vals, y_vals = [], []
    for label, metrics in scenario.items():
        if label in SIZE_MAP and isinstance(metrics, dict):
            ct = metrics.get("completion_time_s")
            if ct is not None:
                x_vals.append(SIZE_MAP[label])
                y_vals.append(ct)

    paired = sorted(zip(x_vals, y_vals))
    if paired:
        x, y = zip(*paired)
        x, y = list(x), list(y)
    else:
        x, y = [], []

    labels = [f"{xi} KB" if xi < 1024 else "1 MB" for xi in x]

    fig, ax = plt.subplots()
    _apply_style()
    fig.patch.set_facecolor(STYLE["figure.facecolor"])
    ax.set_facecolor(STYLE["axes.facecolor"])

    if x and y:
        ax.plot(range(len(x)), y, "D-", color="#c084fc", label="Tamamlanma Süresi")
        ax.fill_between(range(len(x)), y, alpha=0.15, color="#c084fc")
        for i, (xi, yi) in enumerate(zip(labels, y)):
            ax.annotate(
                f"{yi:.2f}s",
                (i, yi), textcoords="offset points",
                xytext=(0, 10), ha="center", fontsize=9, color="#c084fc",
            )
        ax.set_xticks(range(len(x)))
        ax.set_xticklabels(labels)
    else:
        ax.text(0.5, 0.5, "Veri bulunamadi",
                ha="center", va="center", transform=ax.transAxes,
                color="#888888", fontsize=14)

    ax.set_xlabel("Dosya Boyutu", fontsize=11)
    ax.set_ylabel("Tamamlanma Süresi (s)", fontsize=11)
    ax.set_title("Dosya Boyutu vs Tamamlanma Süresi\n(kayip yok, GBN w=4, chunk=1024)",
                 fontsize=12, fontweight="bold")
    ax.grid(True)
    ax.legend(loc="upper left")
    _add_watermark(ax)
    fig.tight_layout()

    return _save(fig, "completion_vs_filesize.png")


# ---------------------------------------------------------------------------
# Ana Fonksiyon
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Argümanlari ayristirir, JSON'u okur ve 4 grafigi üretir.
    """
    parser = argparse.ArgumentParser(
        prog="analyze.py",
        description="NetProbe deney sonuclarini grafikle analiz eder",
    )
    parser.add_argument(
        "--input", "-i",
        default=os.path.join(REPORT_DIR, "experiments.json"),
        metavar="DOSYA",
        help="experiments.json dosyasi (varsayilan: reports/experiments.json)",
    )
    args = parser.parse_args()

    # matplotlib kontrolü
    if not _MPL_OK:
        print(
            f"{RED}[HATA] matplotlib bulunamadi.\n"
            f"       Kurmak icin: pip install matplotlib{RESET}"
        )
        sys.exit(1)

    # JSON yükle
    if not os.path.isfile(args.input):
        print(
            f"{RED}[HATA] Deney dosyasi bulunamadi: {args.input}\n"
            f"       Once 'python run_experiments.py' calistirin.{RESET}"
        )
        sys.exit(1)

    with open(args.input, encoding="utf-8") as fh:
        data = json.load(fh)

    os.makedirs(REPORT_DIR, exist_ok=True)

    # Grafik üret
    plots = [
        ("Throughput vs Chunk Boyutu",    plot_throughput_vs_chunksize),
        ("Retransmission vs Timeout",     plot_retransmission_vs_timeout),
        ("Goodput vs Kayip Orani",        plot_goodput_vs_lossrate),
        ("Tamamlanma Süresi vs Boyut",    plot_completion_vs_filesize),
    ]

    border = "=" * 56
    print(f"\n{BOLD}{CLASS_C}{border}{RESET}")
    print(f"{BOLD}{CLASS_C}  NetProbe Analiz -- BTU Bilgisayar Aglari{RESET}")
    print(f"{BOLD}{CLASS_C}{border}{RESET}")
    print(f"  Kaynak: {args.input}\n")

    all_ok = True
    for title, fn in plots:
        try:
            path = fn(data)
            print(f"  {GREEN}[OK]{RESET} {title}")
            print(f"       -> {path}")
        except Exception as exc:
            print(f"  {RED}[HATA]{RESET} {title}: {exc}")
            all_ok = False

    print()
    if all_ok:
        print(f"{GREEN}  4 grafik basariyla uretildi -> {REPORT_DIR}{RESET}\n")
    else:
        print(f"{RED}  Bazi grafikler üretilemedi.{RESET}\n")


# ---------------------------------------------------------------------------
# Giris Noktasi
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()

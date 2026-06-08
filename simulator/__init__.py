# simulator/__init__.py
"""
simulator
=========
NetProbe ag kosulu simülatörü paketi.

Bu paket, gercek ag kaybi ve gecikmesini taklit ederek
protokolün farkli kosullar altindaki davranisini test etmeyi saglar.

Kullanim:
    from simulator.network_emulator import NetworkEmulator

    emulator = NetworkEmulator(loss_prob=0.1, delay_ms=50)
    wrapped_sock = emulator.wrap_socket(real_sock)
    # wrapped_sock, gercek sock ile ayni arayüzü sunar
"""

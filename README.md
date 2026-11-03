# dhcp_spoofing.py — Rogue DHCP server (lab)

Servidor DHCP **falso** (rogue) para laboratorio de ataques de Capa 2. Responde a
los clientes de una LAN antes que el servidor legítimo y les entrega un **gateway
y DNS apuntando al atacante**, habilitando un MITM (man-in-the-middle) por la vía
DHCP. Incluye un modo **clone** que roba la identidad (IP/MAC/`server_id`) del
servidor legítimo para pasar desapercibido ante detectores basados en whitelist.

> ⚠️ **Solo para laboratorio autorizado.** Esta herramienta se desarrolló como
> parte de un roadmap de formación en ciberseguridad y se prueba exclusivamente en
> una red aislada (`redzone`, `10.10.10.0/24`) entre VMs propias. Usarla contra una
> red que no te pertenece es ilegal. El valor pedagógico real está en el **detector**
> que la caza (repo `dhcp-spoofing-detector`).

---

## Qué hace

El rogue aprovecha que el **DHCP Discover es broadcast**: cualquiera en la VLAN lo
escucha y puede contestar. Si el rogue responde primero (o calla al server real con
starvation), la víctima acepta su Offer y configura como gateway/DNS la IP del
atacante. El secuestro **no** está en la IP ofrecida (`yiaddr`), sino en las
opciones `router` y `name_server`.

## Dependencias

- Python 3
- [Scapy](https://scapy.net/) (`pip install scapy`)
- Privilegios de root (sniffing + envío de tramas crudas)

## Uso

```bash
sudo python3 dhcp_spoofing.py -r <IP/máscara> [-i IFACE] [-d SEG] [-l SEG] [-c]
```

| Flag | Descripción | Default |
|------|-------------|---------|
| `-r`, `--red` | **(requerido)** IP que repartís + máscara, formato `x.x.x.x/nn` (ej. `10.10.10.50/24`). Debe ser RFC1918. | — |
| `-i`, `--iface` | Interfaz de red por donde atacás. | `eth0` |
| `-d`, `--duration` | Segundos que corre (`0` = infinito). | `10` |
| `-l`, `--lease` | Duración del préstamo ofrecido (segundos). | `86400` |
| `-c`, `--clone` | Activa el **modo clone** (ver abajo). | off |

### Ejemplos

```bash
# Rogue ingenuo: ataca con tu propia identidad (IP/MAC del atacante)
sudo python3 dhcp_spoofing.py -r 10.10.10.50/24 -i eth0 -d 60

# Rogue clone: roba la identidad del server legítimo antes de atacar
sudo python3 dhcp_spoofing.py -r 10.10.10.50/24 -i eth0 -c -d 60
```

---

## Los dos modos

### 1. Ingenuo (sin `-c`)

1. Sniffa `udp and (port 67 or port 68)`.
2. Ante un **Discover (1)** o **Request (3)** del cliente, arma un **Offer/Ack**.
3. El Offer lleva `router` y `name_server` = **IP del atacante** (el veneno), pero
   `Ether.src` e `IP.src` también son del atacante → **detectable** por un detector
   que compare la identidad contra una whitelist (IP/MAC desconocidas).

### 2. Clone (`-c`) — evasión por identidad robada

Trabaja en **dos fases**:

**Fase A — Capturar la identidad del server legítimo**
1. Genera un `xid` propio y manda su **propio Discover** (`send_discover`).
2. Sniffa los Offers y acepta solo el que coincide con **su** `xid` (`look_offer`),
   así captura determinísticamente la respuesta del server real.
3. `get_data` guarda `server_id`, `server_mac` (`Ether.src`), `yiaddr` y las opciones.
4. Un `stop_filter` corta la sniff **apenas** captura (no espera el timeout entero).
   Si no capturó nada → "No se pudo clonar" y sale (evita servir con `Ether(src=None)`).

**Fase B — Servir con disfraz**
5. Vuelve a escuchar a los clientes y responde, pero ahora `armar_respuesta` se
   disfraza: `Ether.src` = **MAC del server legítimo**, `IP.src`/`siaddr`/`server_id`
   = **IP del server legítimo**.
6. **Clave del MITM:** `router` y `name_server` **siguen siendo la IP del atacante**.
   No se clonan — son el veneno.

Resultado: un Offer con **identidad idéntica** a la del server real (pasa la whitelist
de un detector v1) pero con **gateway/DNS envenenados**. Esa es la señal que destapa
el detector v2: *identidad confiable + gateway/DNS que no matchea el real*.

---

## Detalles de implementación

- **Validación RFC1918 propia:** `validate_ip` chequea octetos, máscara coherente por
  clase privada (10/8, 172.16–31/12, 192.168/16) y rechaza IPs públicas.
- **Cálculo a mano** de broadcast (`get_broadcast`) y máscara (`prefix_to_netmask`)
  con operaciones de bits, sin `ipaddress`.
- **Estado centralizado** en un dict (`crear_estado`): separa *lo del atacante* (no se
  pisa) de *lo capturado del server* (lo llena `get_data` solo en modo clone).
- `renewal_time`/`rebinding_time` están hardcodeados (pendiente: pasarlos por args).

## Piezas de testeo

- `send_discover` también funciona como disparador manual de un Discover para probar
  el rogue sin un cliente real (en el lab se usó un helper `send_discover.py` aparte).

---

## Relacionado

- **Detector que lo caza:** repo `dhcp-spoofing-detector` (`dhcp_spoofing_detector.py`).
- **Mitigación real (en switch):** DHCP Snooping — confía por **puerto físico**, no
  por identidad (que es falsificable desde software). Este rogue clone muestra por qué
  un detector de host es inherentemente más débil que el snooping del switch.

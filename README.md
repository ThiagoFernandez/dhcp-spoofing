# DHCP Spoofing — rogue DHCP server (ataque de capa 2)

Servidor DHCP falso (*rogue*) sobre IPv4, escrito en Python + Scapy, con dos modos de ataque:
**ingenuo** y **clonación de identidad**. Herramienta educativa para estudiar cómo un atacante
envenena la configuración de red de las víctimas (gateway y DNS → MITM).

> ⚠️ **Uso autorizado y en laboratorio únicamente.** Esta herramienta levanta un servidor DHCP
> falso que envenena la configuración de red de otros equipos (gateway y DNS → MITM). Corré esto
> **solo** en una red aislada de tu propiedad o sobre la que tengas permiso explícito por escrito
> (un lab, una VM, un CTF). Usarla contra redes o equipos ajenos es ilegal. El autor no se hace
> responsable del mal uso.

---

## Qué hace

En DHCP, un cliente que arranca sin IP hace el intercambio **DORA**: `Discover → Offer → Request → Ack`.
El cliente acepta el **primer** Offer que le llega. Un *rogue DHCP* explota eso: contesta más rápido
que el servidor legítimo y le entrega a la víctima una configuración envenenada —`gateway` y `DNS`
apuntando al atacante— con lo que todo el tráfico de salida de la víctima pasa a transitar por él
(**man-in-the-middle**).

Dos modos en un solo script:

### Modo ingenuo (por defecto)
Escucha `Discover`/`Request` de clientes y responde con un Offer/Ack usando **su propia identidad**
(IP y MAC del atacante), pero con `router` y `name_server` apuntándose a sí mismo. Simple y efectivo
contra una red sin defensas, pero fácil de detectar: el Offer sale de un servidor desconocido.

### Modo clonación (`-c`)
Se **hace pasar por el servidor legítimo** para evadir la detección basada en identidad:

1. **Sniffing activo:** manda su propio `Discover` con un `xid` aleatorio que guarda, para provocar
   que el servidor legítimo conteste.
2. **Captura dirigida:** entre todos los Offers de la red, se queda **solo** con el que trae *su*
   `xid` (la respuesta a su Discover), y de ahí roba la identidad del servidor: `server-id`, IP y MAC.
3. **Ataque disfrazado:** empieza a servir Offers a las víctimas con la **identidad robada**
   (MAC + IP + `server-id` del legítimo)… pero `router` y `name_server` siguen apuntando al atacante.

Ese desajuste —identidad del servidor legítimo, pero gateway/DNS traidores— es justamente lo que un
detector puede cazar (ver el proyecto compañero de detección).

Para evitar la *race condition* entre enviar el Discover y empezar a escuchar, el Discover se dispara
desde el `started_callback` del sniffer, es decir en el instante exacto en que la captura ya está lista.

---

## Requisitos

- Linux (probado en Kali)
- Python 3.10+
- [Scapy](https://scapy.net/) — `pip install scapy`
- Privilegios de root (captura y envío de paquetes crudos)

```bash
pip install scapy
```

---

## Uso

```bash
# Modo ingenuo: rogue con identidad propia
sudo python3 dhcp_spoofing.py -r 10.10.10.50/24 -i eth0 -d 60

# Modo clonación: roba la identidad del servidor legítimo y lo suplanta
sudo python3 dhcp_spoofing.py -r 10.10.10.50/24 -i eth0 -c -d 60
```

| Flag | Descripción | Default |
|------|-------------|---------|
| `-r, --red` | IP de host a repartir + máscara (`x.x.x.x/nn`, solo rangos privados RFC1918) | *(requerido)* |
| `-i, --iface` | Interfaz de red | `eth0` |
| `-d, --duration` | Segundos de ejecución (`0` = infinito) | `10` |
| `-l, --lease` | Duración del lease en segundos | `86400` |
| `-c, --clone` | Activa el modo clonación de identidad | off |

---

## Montaje del laboratorio

- Una red aislada (bridge/VM/namespaces) con:
  - un **servidor DHCP legítimo**,
  - una o más **víctimas** (clientes DHCP),
  - el **atacante** corriendo este script.
- Servidor, cliente y atacante tienen que compartir el **mismo dominio de broadcast** (capa 2),
  porque DHCP se descubre por broadcast.

### Verificar el ataque

Con `tcpdump` se ve el Offer envenenado que sirve el atacante:

```bash
sudo tcpdump -i eth0 -e -n 'port 67 or port 68' -vv
```

En modo clonación, el Offer del atacante sale con la **MAC de origen del servidor legítimo** y su
`Server-ID`, pero con `Default-Gateway` y `Domain-Name-Server` apuntando al atacante. Además suele
**ganarle la carrera** al servidor legítimo (contesta primero), por lo que la víctima toma su oferta.

---

## Estado

- [x] Rogue ingenuo
- [x] Rogue con clonación de identidad (sniffing activo + matcheo por `xid`)

La detección de este ataque vive en un repositorio aparte.

---

## Qué aprendí

- El mecanismo DORA y por qué "el primero que contesta gana".
- Diferencia entre la **identidad** de un Offer (MAC/IP/server-id, útil para evadir detección) y su
  **payload de ataque** (gateway/DNS, lo que de verdad desvía el tráfico).
- Perspectiva cliente vs servidor al forjar paquetes (`op`, puertos 67/68, `chaddr`, `xid`).
- Captura dirigida por `xid` para quedarse con la respuesta propia entre muchas.
- Race conditions de sniff/send y cómo resolverlas con `started_callback`.

---

## Licencia

MIT. Solo para fines educativos y de investigación autorizada.

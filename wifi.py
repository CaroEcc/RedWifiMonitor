"""Lectura del estado de la red WiFi.

- Windows: netsh (viene con el sistema).
- Linux: iw (más datos: dBm y velocidades) o, si no está, nmcli (NetworkManager).
"""

import os
import platform
import re
import socket
import struct
import subprocess
from dataclasses import dataclass

SISTEMA = platform.system().lower()

_LINEA = re.compile(r"^\s*(.+?)\s+:\s(.*)$")


@dataclass
class EstadoWifi:
    interfaz: str = ""
    conectado: bool = False
    ssid: str = ""
    bssid: str = ""
    senal: int | None = None  # porcentaje
    rssi: int | None = None  # dBm
    canal: str = ""
    banda: str = ""
    rx_mbps: float | None = None
    tx_mbps: float | None = None


def _numero(texto: str) -> float | None:
    m = re.search(r"-?\d+(?:[.,]\d+)?", texto)
    return float(m.group().replace(",", ".")) if m else None


def _ejecutar(cmd: list[str], **kwargs) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=10, **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def soportado() -> bool:
    return SISTEMA in ("windows", "linux")


def leer_wifi() -> EstadoWifi | None:
    """Estado de la interfaz WiFi (la conectada si hay varias). None si no hay WiFi."""
    if SISTEMA == "windows":
        return _leer_windows()
    if SISTEMA == "linux":
        return _leer_linux()
    return None


def puerta_de_enlace(interfaz: str) -> str | None:
    """IP del router (gateway por defecto) de esa interfaz."""
    if SISTEMA == "windows":
        return _gateway_windows(interfaz)
    if SISTEMA == "linux":
        return _gateway_linux(interfaz)
    return None


# ---------------------------------------------------------------- Windows

def _parsear_netsh(salida: str) -> list[EstadoWifi]:
    interfaces: list[EstadoWifi] = []
    for linea in salida.splitlines():
        m = _LINEA.match(linea)
        if not m:
            continue
        clave, valor = m.group(1).strip().lower(), m.group(2).strip()

        # Cada interfaz empieza con "Name" / "Nombre"
        if clave in ("name", "nombre"):
            interfaces.append(EstadoWifi(interfaz=valor))
            continue
        if not interfaces:
            continue
        e = interfaces[-1]

        if clave in ("state", "estado"):
            e.conectado = valor.lower() in ("connected", "conectado")
        elif clave == "ssid":
            e.ssid = valor
        elif "bssid" in clave:
            e.bssid = valor
        elif clave == "rssi":
            e.rssi = int(_numero(valor) or 0)
        elif valor.endswith("%"):  # "Signal" / "Señal"
            e.senal = int(_numero(valor) or 0)
        elif clave in ("channel", "canal"):
            e.canal = valor
        elif clave in ("band", "banda"):
            e.banda = valor
        elif "mbps" in clave and ("receive" in clave or "recep" in clave):
            e.rx_mbps = _numero(valor)
        elif "mbps" in clave and ("transmit" in clave or "transmis" in clave):
            e.tx_mbps = _numero(valor)
    return interfaces


def _leer_windows() -> EstadoWifi | None:
    salida = _ejecutar(["netsh", "wlan", "show", "interfaces"], encoding="oem", errors="replace")
    interfaces = _parsear_netsh(salida or "")
    if not interfaces:
        return None
    return next((i for i in interfaces if i.conectado), interfaces[0])


def _gateway_windows(interfaz: str) -> str | None:
    comando = (
        f"(Get-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias '{interfaz}' "
        "-ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop"
    )
    salida = _ejecutar(["powershell", "-NoProfile", "-Command", comando], text=True)
    ip = (salida or "").strip()
    return ip if ip and ip != "0.0.0.0" else None


# ---------------------------------------------------------------- Linux

# Salida de los comandos siempre en inglés, para poder leerla
_ENV_C = {**os.environ, "LC_ALL": "C"}


def _interfaces_wifi_linux() -> list[str]:
    try:
        return sorted(i for i in os.listdir("/sys/class/net") if os.path.isdir(f"/sys/class/net/{i}/wireless"))
    except OSError:
        return []


def _dbm_a_porcentaje(dbm: int) -> int:
    # Misma escala aproximada que usa NetworkManager: -100 dBm = 0%, -50 dBm = 100%
    return max(0, min(100, 2 * (dbm + 100)))


def _canal_y_banda(mhz: float) -> tuple[str, str]:
    if 2400 <= mhz < 2500:
        return str(14 if mhz == 2484 else int((mhz - 2407) / 5)), "2.4 GHz"
    if 5000 <= mhz < 5900:
        return str(int((mhz - 5000) / 5)), "5 GHz"
    if 5925 <= mhz < 7200:
        return str(int((mhz - 5950) / 5)), "6 GHz"
    return "", ""


def _parsear_iw(interfaz: str, salida: str) -> EstadoWifi:
    """Salida de `iw dev <interfaz> link`."""
    e = EstadoWifi(interfaz=interfaz)
    for linea in salida.splitlines():
        linea = linea.strip()
        if linea.startswith("Connected to "):
            e.conectado = True
            e.bssid = linea.split()[2]
        elif linea.startswith("SSID:"):
            e.ssid = linea[5:].strip()
        elif linea.startswith("freq:"):
            e.canal, e.banda = _canal_y_banda(_numero(linea) or 0)
        elif linea.startswith("signal:"):
            e.rssi = int(_numero(linea) or 0)
            e.senal = _dbm_a_porcentaje(e.rssi)
        elif linea.startswith("rx bitrate:"):
            e.rx_mbps = _numero(linea)
        elif linea.startswith("tx bitrate:"):
            e.tx_mbps = _numero(linea)
    return e


def _parsear_nmcli(interfaz: str, salida: str) -> EstadoWifi:
    """Salida de `nmcli -t -f ACTIVE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL dev wifi list ifname <interfaz>`."""
    e = EstadoWifi(interfaz=interfaz)
    for linea in salida.splitlines():
        # En modo -t los ":" de los valores (p. ej. el BSSID) vienen escapados como "\:"
        campos = [c.replace("\\:", ":") for c in re.split(r"(?<!\\):", linea)]
        if len(campos) < 7 or campos[0] != "yes":
            continue
        e.conectado = True
        e.ssid, e.bssid, e.canal = campos[1], campos[2], campos[3]
        _, e.banda = _canal_y_banda(_numero(campos[4]) or 0)
        # nmcli solo informa una velocidad y no da dBm
        e.rx_mbps = e.tx_mbps = _numero(campos[5])
        e.senal = int(_numero(campos[6]) or 0)
        break
    return e


def _leer_linux() -> EstadoWifi | None:
    interfaces = _interfaces_wifi_linux()
    if not interfaces:
        return None

    estados = []
    for interfaz in interfaces:
        salida = _ejecutar(["iw", "dev", interfaz, "link"], text=True, env=_ENV_C)
        if salida is not None:
            estados.append(_parsear_iw(interfaz, salida))
            continue
        salida = _ejecutar(
            ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL",
             "dev", "wifi", "list", "ifname", interfaz, "--rescan", "no"],
            text=True, env=_ENV_C,
        )
        if salida is not None:
            estados.append(_parsear_nmcli(interfaz, salida))

    if not estados:
        return None
    return next((e for e in estados if e.conectado), estados[0])


def _parsear_rutas(contenido: str, interfaz: str) -> str | None:
    """Contenido de /proc/net/route: busca la ruta por defecto de la interfaz."""
    for linea in contenido.splitlines()[1:]:
        campos = linea.split()
        if len(campos) >= 3 and campos[0] == interfaz and campos[1] == "00000000":
            ip = socket.inet_ntoa(struct.pack("<L", int(campos[2], 16)))
            if ip != "0.0.0.0":
                return ip
    return None


def _gateway_linux(interfaz: str) -> str | None:
    try:
        with open("/proc/net/route", encoding="ascii") as f:
            return _parsear_rutas(f.read(), interfaz)
    except OSError:
        return None

"""Lectura del estado de la red WiFi en Windows usando netsh (sin instalar nada)."""

import re
import subprocess
from dataclasses import dataclass

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


def _parsear(salida: str) -> list[EstadoWifi]:
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


def leer_wifi() -> EstadoWifi | None:
    """Estado de la interfaz WiFi (la conectada si hay varias). None si no hay WiFi."""
    try:
        r = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, encoding="oem", errors="replace", timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    interfaces = _parsear(r.stdout)
    if not interfaces:
        return None
    return next((i for i in interfaces if i.conectado), interfaces[0])


def puerta_de_enlace(interfaz: str) -> str | None:
    """IP del router (gateway por defecto) de esa interfaz."""
    comando = (
        f"(Get-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias '{interfaz}' "
        "-ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", comando],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    ip = r.stdout.strip()
    return ip if ip and ip != "0.0.0.0" else None

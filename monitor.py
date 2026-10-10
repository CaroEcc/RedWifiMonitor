"""Monitor de red: revisa equipos por ping o puerto TCP y la red WiFi, y avisa por Telegram cuando cambian de estado."""

import csv
import logging
import os
import platform
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime

import requests
from dotenv import load_dotenv

from wifi import EstadoWifi, leer_wifi, puerta_de_enlace
from wifi import soportado as wifi_soportado

load_dotenv()

INTERVALO = float(os.getenv("INTERVALO_SEGUNDOS", "5"))
TIMEOUT = float(os.getenv("TIMEOUT_SEGUNDOS", "2"))
FALLOS_PARA_CAIDA = int(os.getenv("FALLOS_PARA_CAIDA", "3"))
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
LOG_ARCHIVO = os.getenv("LOG_ARCHIVO", "monitor.log")
MONITOREAR_WIFI = os.getenv("MONITOREAR_WIFI", "1").strip().lower() in ("1", "si", "sí", "true")
SENAL_MINIMA = int(os.getenv("SENAL_MINIMA", "40"))
HISTORIAL_WIFI = os.getenv("HISTORIAL_WIFI", "wifi_historial.csv")

SISTEMA = platform.system().lower()

# La consola de Windows no siempre usa UTF-8 y fallaría al imprimir los emojis
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_ARCHIVO, encoding="utf-8"),
    ],
)
log = logging.getLogger("monitor")


@dataclass
class Equipo:
    nombre: str
    host: str
    puerto: int | None = None
    activo: bool | None = None  # None = aún no se sabe
    fallos_seguidos: int = 0
    caido_desde: float | None = None


def hay_ping(host: str) -> bool:
    if SISTEMA == "windows":
        # En Windows -w va en milisegundos
        cmd = ["ping", "-n", "1", "-w", str(int(TIMEOUT * 1000)), host]
    elif SISTEMA == "darwin":
        # En macOS -W va en milisegundos
        cmd = ["ping", "-c", "1", "-W", str(int(TIMEOUT * 1000)), host]
    else:
        # En Linux -W va en segundos
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(TIMEOUT))), host]

    resultado = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
    if resultado.returncode != 0:
        return False
    # En Windows, "Host de destino inaccesible" puede devolver código 0: solo
    # cuenta como respuesta real si aparece el TTL.
    if SISTEMA == "windows":
        return "ttl=" in resultado.stdout.lower()
    return True


def puerto_abierto(host: str, puerto: int) -> bool:
    try:
        with socket.create_connection((host, puerto), timeout=TIMEOUT):
            return True
    except OSError:
        return False


def revisar(equipo: Equipo) -> bool:
    return puerto_abierto(equipo.host, equipo.puerto) if equipo.puerto else hay_ping(equipo.host)


# Avisos que no se pudieron enviar (p. ej. sin internet); se reintentan después
avisos_pendientes: list[str] = []


def avisar(mensaje: str | None = None) -> None:
    """Envía el mensaje a Telegram. Sin mensaje, solo reintenta los pendientes."""
    if not (TELEGRAM_TOKEN and TELEGRAM_CHAT_ID):
        return
    if mensaje:
        hora = datetime.now().strftime("%H:%M:%S")
        avisos_pendientes.append(f"[{hora}] {mensaje}")
    while avisos_pendientes:
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                data={"chat_id": TELEGRAM_CHAT_ID, "text": avisos_pendientes[0]},
                timeout=10,
            )
            r.raise_for_status()
        except requests.RequestException:
            # Si se cayó internet, Telegram tampoco responde; se reintenta en la próxima vuelta
            return
        avisos_pendientes.pop(0)


def cargar_equipos() -> list[Equipo]:
    """Lee EQUIPOS del .env con formato: Nombre=host[:puerto],Nombre2=host2"""
    texto = os.getenv("EQUIPOS", "DNS Google=8.8.8.8,DNS Cloudflare=1.1.1.1")
    equipos = []
    for item in texto.split(","):
        item = item.strip()
        if not item:
            continue
        nombre, _, destino = item.partition("=")
        if not destino:
            nombre, destino = item, item
        host, _, puerto = destino.strip().partition(":")
        equipos.append(Equipo(nombre.strip(), host, int(puerto) if puerto else None))
    return equipos


def duracion(segundos: float) -> str:
    m, s = divmod(int(segundos), 60)
    h, m = divmod(m, 60)
    return f"{h}h {m}m {s}s" if h else f"{m}m {s}s" if m else f"{s}s"


def actualizar(equipo: Equipo, ok: bool) -> None:
    destino = f"{equipo.host}:{equipo.puerto}" if equipo.puerto else equipo.host

    if ok:
        equipo.fallos_seguidos = 0
        if equipo.activo is not True:
            if equipo.activo is False and equipo.caido_desde:
                msg = f"✅ {equipo.nombre} ({destino}) ARRIBA otra vez, estuvo caído {duracion(time.time() - equipo.caido_desde)}"
                avisar(msg)
            else:
                msg = f"{equipo.nombre} ({destino}) ARRIBA"
            log.info(msg)
            equipo.activo = True
            equipo.caido_desde = None
        return

    equipo.fallos_seguidos += 1
    # Solo se declara caído tras varios fallos seguidos, para evitar falsos positivos
    if equipo.activo is not False and equipo.fallos_seguidos >= FALLOS_PARA_CAIDA:
        equipo.activo = False
        equipo.caido_desde = time.time()
        msg = f"⚠️ {equipo.nombre} ({destino}) CAÍDO ({equipo.fallos_seguidos} fallos seguidos)"
        log.info(msg)
        avisar(msg)


class MonitorWifi:
    """Sigue la red WiFi: desconexiones, cambio de red o de punto de acceso y señal débil."""

    def __init__(self) -> None:
        self.anterior: EstadoWifi | None = None
        self.desconectado_desde: float | None = None
        self.senal_debil = False
        self.sin_interfaz = False
        # El router de la red actual se revisa por ping como un equipo más
        self.router = Equipo("Router WiFi", "")

    def _resumen(self, e: EstadoWifi) -> str:
        velocidad = f"{e.rx_mbps:g}/{e.tx_mbps:g} Mbps" if e.rx_mbps is not None and e.tx_mbps is not None else "velocidad ?"
        return f"señal {e.senal}% ({e.rssi} dBm), canal {e.canal} {e.banda}, {velocidad}"

    def _nueva_red(self, e: EstadoWifi) -> None:
        gateway = puerta_de_enlace(e.interfaz) or ""
        self.router = Equipo("Router WiFi", gateway)
        log.info(f"📶 Conectada a «{e.ssid}» (router {gateway or 'desconocido'}), {self._resumen(e)}")

    def guardar_historial(self, e: EstadoWifi) -> None:
        nuevo = not os.path.exists(HISTORIAL_WIFI)
        with open(HISTORIAL_WIFI, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if nuevo:
                w.writerow(["fecha", "conectado", "ssid", "bssid", "canal", "banda",
                            "senal_pct", "rssi_dbm", "rx_mbps", "tx_mbps", "router_ok"])
            w.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), int(e.conectado),
                        e.ssid, e.bssid, e.canal, e.banda, e.senal, e.rssi,
                        e.rx_mbps, e.tx_mbps, "" if self.router.activo is None else int(self.router.activo)])

    def revisar(self) -> EstadoWifi | None:
        e = leer_wifi()
        if e is None:
            if not self.sin_interfaz:
                log.info("No se encontró ninguna interfaz WiFi (en Linux hace falta tener iw o nmcli)")
                self.sin_interfaz = True
            self.anterior = None
            return None
        self.sin_interfaz = False

        a = self.anterior
        if not e.conectado:
            if a is None or a.conectado:
                self.desconectado_desde = time.time()
                red = f" de «{a.ssid}»" if a and a.ssid else ""
                msg = f"📵 WiFi DESCONECTADO{red}"
                log.info(msg)
                avisar(msg)
        else:
            if a is None or not a.conectado:
                if self.desconectado_desde:
                    msg = f"📶 WiFi reconectado a «{e.ssid}», estuvo desconectado {duracion(time.time() - self.desconectado_desde)}"
                    log.info(msg)
                    avisar(msg)
                    self.desconectado_desde = None
                self._nueva_red(e)
            elif e.ssid != a.ssid:
                msg = f"🔀 Cambio de red WiFi: «{a.ssid}» → «{e.ssid}»"
                log.info(msg)
                avisar(msg)
                self._nueva_red(e)
            elif e.bssid != a.bssid:
                log.info(f"📡 Cambio de punto de acceso en «{e.ssid}»: {a.bssid} → {e.bssid}, {self._resumen(e)}")

            # Señal débil con margen de 10 puntos, para no avisar a cada rato si oscila en el límite
            if e.senal is not None:
                if not self.senal_debil and e.senal < SENAL_MINIMA:
                    self.senal_debil = True
                    msg = f"📉 Señal WiFi débil: {e.senal}% ({e.rssi} dBm) en «{e.ssid}»"
                    log.info(msg)
                    avisar(msg)
                elif self.senal_debil and e.senal >= SENAL_MINIMA + 10:
                    self.senal_debil = False
                    log.info(f"📈 Señal WiFi recuperada: {e.senal}% ({e.rssi} dBm)")

        self.anterior = e
        return e


def main() -> None:
    equipos = cargar_equipos()
    wifi = None
    if MONITOREAR_WIFI:
        if wifi_soportado():
            wifi = MonitorWifi()
        else:
            log.info("El monitoreo de WiFi solo está disponible en Windows y Linux; se omite")

    log.info(f"Monitoreando {len(equipos)} equipos{' + WiFi' if wifi else ''} cada {INTERVALO:g}s (Ctrl+C para salir)")
    if not (TELEGRAM_TOKEN and TELEGRAM_CHAT_ID):
        log.info("Telegram no configurado: solo se registrará en consola y en el log")

    sin_internet = False
    with ThreadPoolExecutor(max_workers=min(32, len(equipos) + 1)) as ex:
        while True:
            estado_wifi = wifi.revisar() if wifi else None
            wifi_caido = estado_wifi is not None and not estado_wifi.conectado

            revisados = list(equipos)
            if wifi and wifi.router.host and not wifi_caido:
                revisados.insert(0, wifi.router)

            if not wifi_caido:
                for equipo, ok in zip(revisados, ex.map(revisar, revisados)):
                    actualizar(equipo, ok)

                # Si todos están caídos, probablemente el problema es tu conexión
                todos_caidos = len(revisados) > 1 and all(e.activo is False for e in revisados)
                if todos_caidos and not sin_internet:
                    log.info("🌐 Todos los equipos caídos: probablemente se cayó TU conexión")
                elif not todos_caidos and sin_internet:
                    log.info("🌐 Conexión recuperada")
                sin_internet = todos_caidos

                avisar()  # reintenta los avisos que quedaron pendientes

            if estado_wifi:
                wifi.guardar_historial(estado_wifi)

            time.sleep(INTERVALO)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Monitor detenido")

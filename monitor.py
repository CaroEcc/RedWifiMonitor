"""Monitor de red: revisa equipos por ping o puerto TCP y la red WiFi, diagnostica cada caída y avisa por Telegram."""

import csv
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturoTimeout
from dataclasses import dataclass
from datetime import datetime

import requests
from dotenv import load_dotenv

from diagnostico import TIPOS, Incidente, Muestra, dns_ok, explicar, internet_ok, motivos_sistema, red_visible
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
INCIDENTES_ARCHIVO = os.getenv("INCIDENTES_ARCHIVO", "incidentes.csv")

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
    aviso_caida: bool = False  # si se avisó la caída, se avisa también cuando vuelve


_TIEMPO_PING = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms?\b", re.I)


def medir_ping(host: str) -> float | None:
    """Tiempo de respuesta en ms, o None si no responde."""
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
        return None
    salida = resultado.stdout
    # En Windows, "Host de destino inaccesible" puede devolver código 0: solo
    # cuenta como respuesta real si aparece el TTL.
    if SISTEMA == "windows" and "ttl=" not in salida.lower():
        return None
    # "time=1.2 ms" / "tiempo=3ms" / "tiempo<1m" (el patrón exige "m" después del número,
    # así que no confunde "bytes=32" ni "ttl=64")
    for linea in salida.splitlines():
        if "ttl" in linea.lower():
            m = _TIEMPO_PING.search(linea)
            if m:
                return float(m.group(1).replace(",", "."))
    return 0.0


def hay_ping(host: str) -> bool:
    return medir_ping(host) is not None


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


def hora(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%H:%M:%S")


def actualizar(equipo: Equipo, ok: bool, en_incidente: bool = False) -> None:
    """Registra el cambio de estado de un equipo. Durante un incidente general no se manda
    un aviso por cada equipo: el diagnóstico del incidente ya lo explica."""
    destino = f"{equipo.host}:{equipo.puerto}" if equipo.puerto else equipo.host

    if ok:
        equipo.fallos_seguidos = 0
        if equipo.activo is not True:
            if equipo.activo is False and equipo.caido_desde:
                msg = f"✅ {equipo.nombre} ({destino}) ARRIBA otra vez, estuvo caído {duracion(time.time() - equipo.caido_desde)}"
                if equipo.aviso_caida:
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
        equipo.aviso_caida = not en_incidente
        msg = f"⚠️ {equipo.nombre} ({destino}) CAÍDO ({equipo.fallos_seguidos} fallos seguidos)"
        log.info(msg)
        if equipo.aviso_caida:
            avisar(msg)


class MonitorWifi:
    """Sigue la red WiFi: desconexiones, cambio de red o de punto de acceso y señal débil."""

    def __init__(self) -> None:
        self.anterior: EstadoWifi | None = None
        self.senal_debil = False
        self.sin_interfaz = False
        self.ultima_busqueda_router = 0.0
        # El router de la red actual se revisa por ping como un equipo más
        self.router = Equipo("Router WiFi", "")

    def _resumen(self, e: EstadoWifi) -> str:
        velocidad = f"{e.rx_mbps:g}/{e.tx_mbps:g} Mbps" if e.rx_mbps is not None and e.tx_mbps is not None else "velocidad ?"
        return f"señal {e.senal}% ({e.rssi} dBm), canal {e.canal} {e.banda}, {velocidad}"

    def buscar_router(self, e: EstadoWifi, forzar: bool = False) -> None:
        """Detecta el router (gateway). Sin forzar, como mucho cada 30 s porque tarda un poco."""
        if not forzar and time.time() - self.ultima_busqueda_router < 30:
            return
        self.ultima_busqueda_router = time.time()
        gateway = puerta_de_enlace(e.interfaz) or ""
        if gateway != self.router.host:
            if gateway and self.router.host:
                log.info(f"El router cambió: {self.router.host} → {gateway}")
            self.router = Equipo("Router WiFi", gateway)

    def _nueva_red(self, e: EstadoWifi) -> None:
        self.buscar_router(e, forzar=True)
        log.info(f"📶 Conectado a «{e.ssid}» (router {self.router.host or 'sin IP todavía'}), {self._resumen(e)}")

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
                red = f" de «{a.ssid}»" if a and a.ssid else ""
                log.info(f"📵 WiFi desconectado{red}")
        else:
            if a is None or not a.conectado:
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


class Incidentes:
    """Detecta caídas de la conexión, junta datos mientras duran y al terminar registra
    qué pasó y por qué pudo ser."""

    CAMPOS = ["inicio", "fin", "duracion_s", "tipo", "red", "senal_antes_pct", "rssi_antes_dbm",
              "latencia_router_max_ms", "red_visible_durante", "motivo_sistema", "causas_probables"]

    def __init__(self) -> None:
        # Lo que pasó en los últimos 2 minutos, para saber cómo estaba todo antes de la caída
        self.muestras: deque[Muestra] = deque(maxlen=max(6, int(120 / max(INTERVALO, 1))))
        self.actual: Incidente | None = None
        self.seguidos = 0

    def actualizar(self, estado: str, e: EstadoWifi | None, router_ok: bool | None, latencia: float | None) -> None:
        if estado == "ok":
            self.seguidos = 0
            if self.actual:
                self._cerrar(e)
        else:
            self.seguidos += 1
            if self.actual is None:
                # Un corte de WiFi es inequívoco; lo demás se confirma con varios fallos seguidos
                if estado == "wifi" or self.seguidos >= FALLOS_PARA_CAIDA:
                    self._abrir(estado)
            elif estado not in self.actual.tipos:
                self.actual.tipos.append(estado)

            if self.actual and estado == "wifi" and self.actual.ssid:
                visible = red_visible(self.actual.ssid)
                if visible is not None:
                    self.actual.red_visible.append(visible)

        if self.actual is None:
            conectado = e is not None and e.conectado
            self.muestras.append(Muestra(
                t=time.time(),
                ssid=e.ssid if conectado else "", bssid=e.bssid if conectado else "",
                canal=e.canal if conectado else "",
                senal=e.senal if conectado else None, rssi=e.rssi if conectado else None,
                router_ok=router_ok, latencia=latencia,
            ))

    def _abrir(self, estado: str) -> None:
        inicio = time.time()
        if estado != "wifi":
            # La falla empezó con el primero de los fallos seguidos
            inicio -= (self.seguidos - 1) * INTERVALO
        self.actual = Incidente(tipo=estado, inicio=inicio, antes=list(self.muestras), tipos=[estado])
        red = f" en «{self.actual.ssid}»" if self.actual.ssid else ""
        msg = f"🔴 CAÍDA: {TIPOS[estado]}{red}"
        log.info(msg)
        avisar(msg)

    def _cerrar(self, e: EstadoWifi | None) -> None:
        inc = self.actual
        self.actual = None
        inc.fin = time.time()
        if e is not None and e.conectado:
            inc.ssid_despues, inc.bssid_despues = e.ssid, e.bssid
        if "wifi" in inc.tipos or "sin_ip" in inc.tipos:
            inc.motivos = motivos_sistema(inc.inicio)
        causas = explicar(inc, SENAL_MINIMA)
        dur = duracion(inc.fin - inc.inicio)

        texto = (f"✅ Conexión recuperada tras {dur}\n"
                 f"Qué pasó: {TIPOS[inc.tipo]}{f' en «{inc.ssid}»' if inc.ssid else ''} "
                 f"(de {hora(inc.inicio)} a {hora(inc.fin)})\n"
                 "Por qué pudo ser:\n" + "\n".join(f"• {c}" for c in causas))
        log.info(texto)
        avisar(texto)
        self._guardar(inc, causas)

    def cerrar_pendiente(self) -> None:
        """Si se detiene el monitor con una caída en curso, queda registrada igual."""
        if self.actual:
            log.info("El monitor se detuvo con una caída en curso; se registra hasta ahora")
            self._cerrar(None)

    def _guardar(self, inc: Incidente, causas: list[str]) -> None:
        senales = [m for m in inc.antes if m.senal is not None]
        latencias = [m.latencia for m in inc.antes if m.latencia is not None]
        visible = "" if not inc.red_visible else "sí" if all(inc.red_visible) else "no"
        nuevo = not os.path.exists(INCIDENTES_ARCHIVO)
        # utf-8-sig para que Excel muestre bien los acentos
        with open(INCIDENTES_ARCHIVO, "a", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            if nuevo:
                w.writerow(self.CAMPOS)
            w.writerow([
                datetime.fromtimestamp(inc.inicio).strftime("%Y-%m-%d %H:%M:%S"),
                datetime.fromtimestamp(inc.fin).strftime("%Y-%m-%d %H:%M:%S"),
                int(inc.fin - inc.inicio), TIPOS[inc.tipo], inc.ssid,
                senales[-1].senal if senales else "", senales[-1].rssi if senales else "",
                f"{max(latencias):.0f}" if latencias else "", visible,
                " | ".join(inc.motivos), " | ".join(causas),
            ])


def guardar_historial(e: EstadoWifi, estado: str, router_ok: bool | None, latencia: float | None) -> None:
    campos = ["fecha", "estado", "conectado", "ssid", "bssid", "canal", "banda", "senal_pct",
              "rssi_dbm", "rx_mbps", "tx_mbps", "router_ok", "latencia_router_ms"]
    if os.path.exists(HISTORIAL_WIFI):
        with open(HISTORIAL_WIFI, encoding="utf-8") as f:
            if f.readline().strip() != ",".join(campos):
                # Historial de una versión anterior con otras columnas: se aparta
                f.close()
                os.replace(HISTORIAL_WIFI, HISTORIAL_WIFI.replace(".csv", "_anterior.csv"))
    nuevo = not os.path.exists(HISTORIAL_WIFI)
    with open(HISTORIAL_WIFI, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if nuevo:
            w.writerow(campos)
        w.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), estado, int(e.conectado),
                    e.ssid, e.bssid, e.canal, e.banda, e.senal, e.rssi, e.rx_mbps, e.tx_mbps,
                    "" if router_ok is None else int(router_ok),
                    "" if latencia is None else f"{latencia:.0f}"])


def main() -> None:
    equipos = cargar_equipos()
    wifi = None
    if MONITOREAR_WIFI:
        if wifi_soportado():
            wifi = MonitorWifi()
        else:
            log.info("El monitoreo de WiFi solo está disponible en Windows y Linux; se omite")
    incidentes = Incidentes()

    log.info(f"Monitoreando {len(equipos)} equipos{' + WiFi' if wifi else ''} cada {INTERVALO:g}s (Ctrl+C para salir)")
    if not (TELEGRAM_TOKEN and TELEGRAM_CHAT_ID):
        log.info("Telegram no configurado: solo se registrará en consola y en el log")

    ex = ThreadPoolExecutor(max_workers=min(32, len(equipos) + 4))
    try:
        while True:
            e = wifi.revisar() if wifi else None
            router_ok = latencia = None

            if e is not None and not e.conectado:
                estado = "wifi"
            else:
                router = wifi.router if wifi else None
                f_router = ex.submit(medir_ping, router.host) if router and router.host else None
                f_internet = ex.submit(internet_ok, TIMEOUT)
                f_dns = ex.submit(dns_ok)
                resultados = list(ex.map(revisar, equipos))

                if f_router:
                    latencia = f_router.result()
                    router_ok = latencia is not None
                hay_internet = f_internet.result()
                try:
                    hay_dns = f_dns.result(timeout=TIMEOUT * 2)
                except FuturoTimeout:
                    hay_dns = False

                if not hay_internet and e is not None:
                    # Sin internet: puede que el router haya cambiado o que no tengamos IP
                    wifi.buscar_router(e)

                if hay_internet:
                    estado = "ok" if hay_dns else "dns"
                elif e is not None and not wifi.router.host:
                    estado = "sin_ip"
                elif router_ok is False:
                    estado = "router"
                else:
                    estado = "internet"

            # Primero el incidente, para que los equipos no avisen uno por uno si es una caída general
            incidentes.actualizar(estado, e, router_ok, latencia)
            if estado != "wifi":
                en_incidente = incidentes.actual is not None
                if wifi and wifi.router.host and router_ok is not None:
                    actualizar(wifi.router, router_ok, en_incidente)
                for equipo, ok in zip(equipos, resultados):
                    actualizar(equipo, ok, en_incidente)
                avisar()  # reintenta los avisos que quedaron pendientes

            if e is not None:
                guardar_historial(e, estado, router_ok, latencia)

            time.sleep(INTERVALO)
    finally:
        incidentes.cerrar_pendiente()
        ex.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Monitor detenido")

"""Diagnóstico de caídas: en qué parte de la red falló y por qué pudo haber sido."""

import os
import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field

from wifi import _interfaces_wifi_linux

SISTEMA = platform.system().lower()

TIPOS = {
    "wifi": "WiFi desconectado",
    "sin_ip": "WiFi conectado pero sin dirección IP",
    "router": "El router no responde",
    "internet": "Sin salida a internet",
    "dns": "Falla de DNS (no se resuelven nombres)",
}


@dataclass
class Muestra:
    """Cómo estaba la conexión en un instante (se guardan las de los últimos minutos)."""
    t: float
    ssid: str = ""
    bssid: str = ""
    canal: str = ""
    senal: int | None = None
    rssi: int | None = None
    router_ok: bool | None = None
    latencia: float | None = None  # ms al router


@dataclass
class Incidente:
    tipo: str
    inicio: float
    antes: list[Muestra] = field(default_factory=list)
    tipos: list[str] = field(default_factory=list)  # todo lo que falló durante el corte, en orden
    red_visible: list[bool] = field(default_factory=list)  # ¿se veía la red durante el corte?
    fin: float | None = None
    ssid_despues: str = ""
    bssid_despues: str = ""
    motivos: list[str] = field(default_factory=list)  # lo que registró el sistema operativo

    @property
    def ssid(self) -> str:
        return next((m.ssid for m in reversed(self.antes) if m.ssid), "")

    @property
    def bssid(self) -> str:
        return next((m.bssid for m in reversed(self.antes) if m.bssid), "")


def _ejecutar(cmd: list[str], **kwargs) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=15, **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


# ---------------------------------------------------------------- Pruebas

def _tcp(host: str, puerto: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, puerto), timeout=timeout):
            return True
    except OSError:
        return False


def internet_ok(timeout: float = 2) -> bool:
    """¿Hay salida a internet? Se prueba por IP, sin depender del DNS."""
    return _tcp("1.1.1.1", 53, timeout) or _tcp("8.8.8.8", 53, timeout)


def dns_ok() -> bool:
    try:
        socket.getaddrinfo("www.google.com", 443)
        return True
    except OSError:
        return False


def red_visible(ssid: str) -> bool | None:
    """¿El WiFi sigue viendo esa red en el aire? None si no se puede saber."""
    if SISTEMA == "windows":
        salida = _ejecutar(["netsh", "wlan", "show", "networks"], encoding="oem", errors="replace")
        if salida is None:
            return None
        redes = {m.group(1).strip() for m in re.finditer(r"^SSID \d+\s*:\s?(.*)$", salida, re.M)}
    elif SISTEMA == "linux":
        salida = _ejecutar(["nmcli", "-t", "-f", "SSID", "dev", "wifi", "list", "--rescan", "auto"], text=True)
        if salida is not None:
            redes = {linea.replace("\\:", ":").strip() for linea in salida.splitlines()}
        else:
            # Sin NetworkManager: redes que el sistema ya detectó (scan dump no necesita root)
            redes = set()
            leido = False
            for interfaz in _interfaces_wifi_linux():
                salida = _ejecutar(["iw", "dev", interfaz, "scan", "dump"], text=True, env={**os.environ, "LC_ALL": "C"})
                if salida is not None:
                    leido = True
                    redes |= {m.group(1).strip() for m in re.finditer(r"^\s*SSID: (.*)$", salida, re.M)}
            if not leido:
                return None
    else:
        return None
    return ssid in redes


# ---------------------------------------------------------------- Motivos del sistema

_CLAVE_MOTIVO = re.compile(r"reason|hint|motivo|raz[oó]n|sugerencia|causa", re.I)
_SIN_PROBLEMA = re.compile(r"successful|correctamente|con éxito|satisfactoria", re.I)
_LINUX_RELEVANTE = re.compile(
    r"reason|deauth|disassoc|beacon|connection to ap .* lost|ctrl-event-disconnected|handshake|"
    r"dhcp.*(fail|timeout)|timed out|link becomes not ready",
    re.I,
)


def motivos_sistema(desde: float) -> list[str]:
    """Lo que el sistema operativo registró sobre el WiFi desde ese momento (con 1 min de margen)."""
    segundos = int(time.time() - desde) + 60
    lineas: list[str] = []

    if SISTEMA == "windows":
        comando = (
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
            "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; "
            f"StartTime=(Get-Date).AddSeconds(-{segundos})}} -ErrorAction SilentlyContinue | "
            "Sort-Object TimeCreated | ForEach-Object { $_.Message }"
        )
        salida = _ejecutar(["powershell", "-NoProfile", "-Command", comando], encoding="utf-8", errors="replace")
        for linea in (salida or "").splitlines():
            clave, sep, valor = linea.partition(":")
            if sep and valor.strip() and _CLAVE_MOTIVO.search(clave) and not _SIN_PROBLEMA.search(valor):
                lineas.append(valor.strip())

    elif SISTEMA == "linux":
        desde_txt = f"-{segundos}s"
        for extra in (["-u", "NetworkManager", "-u", "wpa_supplicant", "-u", "iwd"], ["-k"]):
            salida = _ejecutar(
                ["journalctl", "--since", desde_txt, "--no-pager", "-o", "cat", *extra],
                text=True, env={**os.environ, "LC_ALL": "C"},
            )
            lineas += [l.strip()[:200] for l in (salida or "").splitlines() if _LINUX_RELEVANTE.search(l)]
        lineas = lineas[-6:]

    # Sin repetidos, conservando el orden
    return list(dict.fromkeys(lineas))


def _interpretar_motivo(motivo: str) -> str | None:
    m = motivo.lower()
    if "psk mismatch" in m or "no coincide" in m or "reason=15" in m or "4-way handshake" in m:
        return "la contraseña no coincidió (contraseña cambiada o incorrecta) o falló el saludo de seguridad por interferencia"
    if "by the driver" in m or "controlador" in m:
        return "el adaptador WiFi cortó la conexión; suele pasar por pérdida de señal o por el ahorro de energía del adaptador"
    if "not available" in m or "no está disponible" in m:
        return "la red no estaba disponible (dejó de emitir o quedó fuera de alcance)"
    if "by the user" in m or "usuario" in m:
        return "desconexión manual (alguien desconectó el WiFi o eligió otra red)"
    if "beacon" in m or ("connection to ap" in m and "lost" in m):
        return "se dejó de recibir la señal del punto de acceso"
    if "reason=3" in m or "deauth" in m:
        return "el punto de acceso dio de baja la conexión (se reinició, se apagó o expulsó al equipo)"
    if "reason=4" in m:
        return "el punto de acceso desconectó al equipo por inactividad"
    if "reason=6" in m or "reason=7" in m:
        return "el punto de acceso ya no reconocía al equipo (normalmente porque se reinició)"
    if "dhcp" in m:
        return "no se obtuvo dirección IP del router (DHCP)"
    return None


# ---------------------------------------------------------------- Explicación

def explicar(inc: Incidente, senal_minima: int) -> list[str]:
    """Causas probables del incidente, de la más a la menos probable."""
    causas: list[str] = []
    dur = (inc.fin or time.time()) - inc.inicio
    senales = [m.senal for m in inc.antes if m.senal is not None]
    latencias = [m.latencia for m in inc.antes if m.latencia is not None]
    pruebas_router = [m.router_ok for m in inc.antes if m.router_ok is not None]
    perdidas = pruebas_router.count(False)
    ult = senales[-1] if senales else None
    ult_rssi = next((m.rssi for m in reversed(inc.antes) if m.rssi is not None), None)
    canal = next((m.canal for m in reversed(inc.antes) if m.canal), "")
    dbm = f", {ult_rssi} dBm" if ult_rssi is not None else ""

    if inc.tipo == "wifi":
        if inc.red_visible and not all(inc.red_visible):
            causa = (f"La red «{inc.ssid}» dejó de verse durante el corte → el router/punto de acceso se apagó, "
                     "se reinició o dejó de emitir (corte de energía, reinicio, cambio de configuración o falla del equipo).")
            if 30 <= dur <= 240:
                causa += f" La duración ({int(dur)} s) coincide con lo que tarda un router en reiniciarse."
            causas.append(causa)
        elif inc.red_visible:
            causas.append(f"La red «{inc.ssid}» siguió visible durante el corte → el router seguía encendido; "
                          "falló el enlace entre tu equipo y el router.")

        if ult is not None and ult < senal_minima:
            causas.append(f"La señal era débil justo antes ({ult}%{dbm}) → cobertura insuficiente en este punto: "
                          "acerca el router/AP, cámbialo de lugar (más alto, sin paredes ni metal de por medio) o agrega un repetidor/AP.")
        elif senales and max(senales) - ult >= 25:
            causas.append(f"La señal cayó bruscamente antes del corte ({max(senales)}% → {ult}%) → un obstáculo, "
                          "interferencia (microondas, otros routers en el mismo canal) o el AP bajó su potencia.")
        elif ult is not None and not (inc.red_visible and not all(inc.red_visible)):
            causas.append(f"La señal era buena antes del corte ({ult}%{dbm}), así que no parece un problema de cobertura → "
                          f"revisa interferencia en el canal {canal or '?'}, el ahorro de energía del adaptador WiFi, "
                          "o si el router expulsa equipos (límite de clientes, filtro MAC, reinicios programados).")

        if dur < 15:
            causas.append(f"Fue un corte breve ({int(dur)} s) → típico de interferencia momentánea o de un salto entre puntos de acceso.")
        if inc.bssid_despues and inc.bssid and inc.bssid_despues.lower() != inc.bssid.lower():
            causas.append(f"Volvió conectado a otro punto de acceso ({inc.bssid} → {inc.bssid_despues}) → hay varios "
                          "AP/repetidores con la misma red y el equipo saltó entre ellos.")
        if inc.ssid_despues and inc.ssid and inc.ssid_despues != inc.ssid:
            causas.append(f"Se reconectó a otra red («{inc.ssid_despues}» en vez de «{inc.ssid}»).")

    elif inc.tipo == "sin_ip":
        causas.append("El WiFi estaba conectado pero no se obtuvo dirección IP → el DHCP del router no respondió: router "
                      "saturado o reiniciándose, rango de IPs agotado (demasiados dispositivos) o DHCP mal configurado "
                      "(por ejemplo, dos routers repartiendo IPs en la misma red).")

    elif inc.tipo == "router":
        senal_txt = f" (señal {ult}%{dbm})" if ult is not None else ""
        causas.append(f"El WiFi seguía conectado{senal_txt} pero el router no respondía y no había internet → router colgado, "
                      "saturado o reiniciándose. Si el equipo está conectado a un repetidor o mesh, ese repetidor perdió el enlace con el router principal.")

    elif inc.tipo == "internet":
        lat = f" en {min(latencias):.0f} ms" if latencias else ""
        causas.append(f"La red local funcionaba (el router respondía{lat}) pero no había salida a internet → falla del proveedor, "
                      "del módem/ONT, del cable entre el módem y el puerto WAN del router, o de la configuración WAN/PPPoE del router.")

    elif inc.tipo == "dns":
        causas.append("Había internet pero no se resolvían nombres → el DNS del router o del proveedor falló o está mal configurado. "
                      "Solución: configura los DNS 1.1.1.1 y 8.8.8.8 en el router.")

    # Señales de inestabilidad antes del corte (sirven para cualquier tipo)
    if perdidas >= 2:
        causas.append(f"Antes del corte el router ya no respondía algunas pruebas ({perdidas} de {len(pruebas_router)}) → enlace inestable.")
    if latencias and max(latencias) > 150:
        causas.append(f"La latencia al router fue alta antes del corte (hasta {max(latencias):.0f} ms; lo normal en una red local es menos de 10 ms) "
                      "→ canal WiFi saturado, interferencia o router sobrecargado.")

    for motivo in inc.motivos:
        interpretacion = _interpretar_motivo(motivo)
        causas.append(f"El sistema registró: «{motivo}»" + (f" → {interpretacion}." if interpretacion else "."))

    otros = [TIPOS[t] for t in inc.tipos if t != inc.tipo]
    if otros:
        causas.append("Durante el corte también hubo: " + ", ".join(otros).lower() + ".")

    if not causas:
        causas.append("No hubo datos suficientes para determinar la causa.")
    return causas

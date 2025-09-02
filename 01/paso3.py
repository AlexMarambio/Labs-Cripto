from scapy.all import sniff, ICMP
import requests
from termcolor import colored
import math
import time

# ---- Configuración ----
INTERFAZ = "wlan0"   # cambia por la interfaz que uses
NUM_PAQUETES = 100   # máximo de paquetes ICMP a capturar
TIMEOUT_SILENCIO = 5 # segundos sin tráfico antes de detener

# ---- Función para consultar la RAE API ----
def get_word_definition(word):
    url = f"https://rae-api.com/api/words/{word}"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 404:
            return False
        if response.status_code != 200:
            return False
        return True
    except Exception:
        return False

# ---- Cifrado César ----
def cesar(texto: str, desplazamiento: int) -> str:
    resultado = []
    for ch in texto:
        if ch.isalpha():
            if ch.isupper():
                base = ord('A')
                nuevo = (ord(ch) - base + desplazamiento) % 26 + base
                resultado.append(chr(nuevo))
            else:
                base = ord('a')
                nuevo = (ord(ch) - base - desplazamiento) % 26 + base
                resultado.append(chr(nuevo))
        else:
            resultado.append(ch)
    return ''.join(resultado)

# ---- Evaluación de probabilidad con rachas ----
def evaluar_texto(palabras):
    reales = []
    for p in palabras:
        if len(p) < 3:   # filtrar palabras cortas
            reales.append(False)
        else:
            reales.append(get_word_definition(p.lower()))

    puntaje = 0
    racha = 0

    for es_real in reales:
        if es_real:
            racha += 1
        else:
            if racha > 0:
                puntaje += racha * (racha + 1) // 2
                racha = 0
    if racha > 0:
        puntaje += racha * (racha + 1) // 2

    # normalizar por cantidad de palabras
    return puntaje / max(1, len(palabras))


# ---- Captura ICMP ----
def capturar_mensaje():
    mensaje = []
    ultimo_paquete = [time.time()]

    def procesar(pkt):
        if ICMP in pkt and pkt[ICMP].type == 8:  # Echo Request
            try:
                data = bytes(pkt[ICMP].payload).decode(errors="ignore")
                if data:
                    mensaje.append(data)
                    ultimo_paquete[0] = time.time()
            except:
                pass

    def detener(pkt):
        return (time.time() - ultimo_paquete[0]) > TIMEOUT_SILENCIO or len(mensaje) >= NUM_PAQUETES

    print(f"📡 Escuchando paquetes ICMP en {INTERFAZ}... (Ctrl+C para detener)")
    sniff(filter="icmp", iface=INTERFAZ, prn=procesar, stop_filter=detener)
    return "".join(mensaje)

# ---- Main ----
if __name__ == "__main__":
    texto_capturado = capturar_mensaje()
    print("\n📥 Mensaje capturado (cifrado):", texto_capturado)

    print("\n🔎 Probando desplazamientos 0–25...\n")

    mejores_resultados = []

    for desplazamiento in range(26):
        texto_descifrado = cesar(texto_capturado, desplazamiento)
        palabras = texto_descifrado.split()

        if palabras:
            puntaje = evaluar_texto(palabras)
            mejores_resultados.append((puntaje, desplazamiento, texto_descifrado))

    # Ordenar por puntaje descendente
    mejores_resultados.sort(key=lambda x: x[0], reverse=True)

    # Mostrar el mejor resultado en verde y los demás normales
    mejor_puntaje = mejores_resultados[0][0] if mejores_resultados else 0
    for puntaje, desplazamiento, texto in mejores_resultados:
        if puntaje == mejor_puntaje and puntaje > 0:
            print(colored(f"[{desplazamiento}] (Puntaje={puntaje}) {texto}", "green"))
        else:
            print(f"[{desplazamiento}] (Puntaje={puntaje}) {texto}")

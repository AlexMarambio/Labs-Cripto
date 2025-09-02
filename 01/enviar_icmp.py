from scapy.all import IP, ICMP, send
import sys
import time

def enviar_icmp(texto_cifrado: str, destino: str = "0.0.0.0"):
    for i, ch in enumerate(texto_cifrado):
        paquete = IP(dst=destino)/ICMP()/ch.encode()
        send(paquete, verbose=False)
        print(f"[{i+1}] Caracter enviado: '{ch}'")
        time.sleep(0.5)  # pequeño delay para no saturar

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 enviar_icmp.py \"TEXTO_CIFRADO\" [DESTINO]")
        sys.exit(1)

    texto_cifrado = sys.argv[1]
    destino = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"

    print(f"Enviando texto cifrado: {texto_cifrado} → destino {destino}\n")
    enviar_icmp(texto_cifrado, destino)

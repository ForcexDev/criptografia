#!/usr/bin/env python3
"""
MitM: Captura paquetes ICMP Echo Request, extrae el mensaje cifrado,
reconstruye ordenando por secuencia y aplica fuerza bruta César.
Incluye análisis de frecuencia mediante Chi-cuadrado.
"""

import sys
import struct
import argparse
from scapy.all import sniff, ICMP, rdpcap

# Frecuencias de letras combinadas ES + EN para criptoanálisis clásico
FREQ_REF = {
    'a': 8.2,  'b': 1.5,  'c': 2.8,  'd': 4.3,  'e': 12.7,
    'f': 2.2,  'g': 2.0,  'h': 6.1,  'i': 7.0,  'j': 0.2,
    'k': 0.8,  'l': 4.0,  'm': 2.4,  'n': 6.7,  'o': 7.5,
    'p': 1.9,  'q': 0.1,  'r': 6.0,  's': 6.3,  't': 9.1,
    'u': 2.8,  'v': 1.0,  'w': 2.4,  'x': 0.2,  'y': 2.0,
    'z': 0.1
}

def cifrar_cesar(texto, desplazamiento):
    resultado = []
    for char in texto:
        if char.isalpha():
            inicio = ord('a') if char.islower() else ord('A')
            resultado.append(chr((ord(char) - inicio + desplazamiento) % 26 + inicio))
        else:
            resultado.append(char)
    return ''.join(resultado)

def descifrar_cesar(texto, desplazamiento):
    return cifrar_cesar(texto, -desplazamiento)

def puntuar_frecuencia(texto):
    """
    Puntúa un texto usando la prueba estadística Chi-cuadrado 
    contra las frecuencias esperadas del idioma.
    """
    if not texto:
        return 0

    solo_letras = [c.lower() for c in texto if c.isalpha()]
    if not solo_letras:
        return 0

    total = len(solo_letras)
    conteo = {}
    for c in solo_letras:
        conteo[c] = conteo.get(c, 0) + 1

    chi2 = 0.0
    for letra, freq_esp in FREQ_REF.items():
        observado = (conteo.get(letra, 0) / total) * 100
        esperado = freq_esp
        chi2 += ((observado - esperado) ** 2) / esperado

    validez = sum(1 for c in texto if c.isalpha() or c.isspace()) / len(texto)
    return (1 / (chi2 + 1e-9)) * 1000 + validez * 50

def procesar_paquetes(paquetes, id_esperado):
    """Extrae (seq, char) filtrando por el ID ICMP esperado para evitar ruido."""
    secuencias = []
    for pkt in paquetes:
        if ICMP in pkt and pkt[ICMP].type == 8 and pkt[ICMP].id == id_esperado:
            payload = bytes(pkt[ICMP].payload)
            if len(payload) >= 9:
                seq = struct.unpack("!I", payload[4:8])[0]
                char = payload[8:9].decode('utf-8', errors='ignore')
                if char:
                    secuencias.append((seq, char))
                    print(f"  Extraído: seq={seq}, char='{char}'")
    return secuencias

def reconstruir_mensaje(secuencias):
    if not secuencias:
        return ""
    secuencias.sort(key=lambda x: x[0])
    return ''.join(char for _, char in secuencias)

def capturar_en_vivo(tiempo, id_esperado):
    print(f"\n[*] Escuchando tráfico ICMP (ID={id_esperado}) por {tiempo} segundos...")
    try:
        pkts = sniff(filter="icmp", timeout=tiempo)
    except KeyboardInterrupt:
        print("\n[!] Captura interrumpida.")
        pkts = []
    return procesar_paquetes(pkts, id_esperado)

def leer_pcap(ruta, id_esperado):
    print(f"\n[*] Leyendo paquetes desde: {ruta} (Filtrando ID={id_esperado})\n")
    try:
        pkts = rdpcap(ruta)
    except Exception as e:
        print(f"[!] Error al leer el pcap: {e}")
        sys.exit(1)
    return procesar_paquetes(pkts, id_esperado)

def fuerza_bruta(mensaje_cifrado):
    print(f"\n[*] Mensaje cifrado ({len(mensaje_cifrado)} chars): {mensaje_cifrado}")
    print("\n─── Fuerza bruta César: 26 rotaciones ───\n")

    puntajes = []
    for r in range(26):
        intento = descifrar_cesar(mensaje_cifrado, r)
        puntaje = puntuar_frecuencia(intento)
        puntajes.append((r, intento, puntaje))

    mejor_r, mejor_texto, _ = max(puntajes, key=lambda x: x[2])

    for r, texto, _ in puntajes:
        if r == mejor_r:
            print(f"\033[92mRotación {r:2d}: {texto}\033[0m")
        else:
            print(f"Rotación {r:2d}: {texto}")

    print("\n\033[93m─── Resultado ───\033[0m")
    print(f"Llave (desplazamiento) : {mejor_r}")
    print(f"Mensaje en claro       : {mejor_texto}")

def main():
    parser = argparse.ArgumentParser(description="MitM ICMP - DPI Evasion y Criptoanálisis")
    grupo = parser.add_mutually_exclusive_group()
    grupo.add_argument("--mensaje", metavar="TEXTO", help="Usar mensaje directo")
    grupo.add_argument("--pcap", metavar="ARCHIVO", help="Leer desde pcap")
    parser.add_argument("--tiempo", type=int, default=15, help="Segundos captura")
    parser.add_argument("--id", type=int, default=54321, help="ID ICMP a interceptar")
    args = parser.parse_args()

    if args.mensaje:
        mensaje_cifrado = args.mensaje
    elif args.pcap:
        secuencias = leer_pcap(args.pcap, args.id)
        mensaje_cifrado = reconstruir_mensaje(secuencias)
    else:
        secuencias = capturar_en_vivo(args.tiempo, args.id)
        mensaje_cifrado = reconstruir_mensaje(secuencias)

    if not mensaje_cifrado:
        print("[!] No hay datos para procesar.")
        sys.exit(1)

    fuerza_bruta(mensaje_cifrado)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Envía un mensaje cifrado en paquetes ICMP Echo Request (un carácter por paquete).
"""

import sys
import socket
import struct
import time

def checksum(data):
    """Calcula el checksum ICMP (estándar RFC 792)."""
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i] << 8) + data[i + 1]
    if n:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def crear_paquete_icmp(id_paquete, seq, data_byte, timestamp_fijo):
    """
    Construye un paquete ICMP Echo Request con:
    - type=8, code=0
    - identifier = id_paquete (coherente entre paquetes)
    - sequence = seq (incrementa coherentemente)
    - payload: 8 bytes metadata (timestamp_fijo + seq) + 1 byte del carácter + relleno hasta 56 bytes
    - El relleno (desde offset 0x10 hasta 0x37) es un patrón fijo para simular un ping real.
    """
    # Metadata: 4 bytes timestamp (fijo) + 4 bytes sequence (coherente)
    metadata = struct.pack("!I", timestamp_fijo) + struct.pack("!I", seq)

    # Payload total: 56 bytes (tamaño típico de ping)
    # - 8 bytes metadata
    # - 1 byte del carácter
    # - 47 bytes de relleno (para que desde offset 0x10 a 0x37 quede un patrón fijo)
    #   El offset 0x10 dentro del payload corresponde al byte 16 (0x10) = después de los primeros 16 bytes.
    #   Nos aseguramos de que esos bytes sean predecibles.
    relleno = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvw'  # 47 bytes exactos
    payload = metadata + data_byte + relleno

    # Encabezado ICMP
    icmp_type = 8
    icmp_code = 0
    icmp_checksum = 0
    header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, id_paquete, seq)
    packet = header + payload
    icmp_checksum = checksum(packet)
    header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, id_paquete, seq)
    return header + payload

def enviar_icmp(destino, mensaje_cifrado, id_fijo):
    """Envía cada carácter en un paquete ICMP separado."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Error: Se necesitan permisos de root para raw sockets.")
        print("Ejecuta: sudo python3 pingv4.py ...")
        sys.exit(1)

    # Timestamp fijo para todos los paquetes (mantiene timestamp coherente)
    timestamp_fijo = int(time.time()) & 0xFFFFFFFF

    print(f"Enviando mensaje cifrado: {mensaje_cifrado}")
    print(f"ID fijo: {id_fijo}, Timestamp fijo: {timestamp_fijo}\n")

    for i, char in enumerate(mensaje_cifrado):
        data_byte = char.encode('utf-8')
        paquete = crear_paquete_icmp(id_fijo, i, data_byte, timestamp_fijo)
        sock.sendto(paquete, (destino, 0))
        print(f"Paquete {i+1}: seq={i}, char='{char}'")
        time.sleep(0.1)  # Pequeña pausa para no saturar

    sock.close()
    print(f"\nTotal enviados: {len(mensaje_cifrado)} paquetes")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: sudo python3 pingv4.py \"mensaje_cifrado\" destino_ip id_fijo")
        print("Ejemplo: sudo python3 pingv4.py \"larycxpajorj\" 8.8.8.8 12345")
        sys.exit(1)

    mensaje = sys.argv[1]
    destino = sys.argv[2]
    id_fijo = int(sys.argv[3])
    enviar_icmp(destino, mensaje, id_fijo)

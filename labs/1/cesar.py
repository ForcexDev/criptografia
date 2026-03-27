#!/usr/bin/env python3

import sys

def cifrar_cesar(texto, desplazamiento):
    """Cifra texto usando desplazamiento en alfabeto inglés."""
    resultado = []
    for char in texto:
        if char.isalpha():
            inicio = ord('a') if char.islower() else ord('A')
            resultado.append(chr((ord(char) - inicio + desplazamiento) % 26 + inicio))
        else:
            resultado.append(char)
    return ''.join(resultado)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py \"texto\" desplazamiento")
        sys.exit(1)

    texto = sys.argv[1]
    desplazamiento = int(sys.argv[2])
    cifrado = cifrar_cesar(texto, desplazamiento)
    print(f"Texto cifrado: {cifrado}")

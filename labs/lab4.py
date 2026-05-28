from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def ajustar_clave(clave_str, tamano):
    clave = clave_str.encode('utf-8')
    if len(clave) < tamano:
        clave = clave + get_random_bytes(tamano - len(clave))
    elif len(clave) > tamano:
        clave = clave[:tamano]
    return clave

def ajustar_iv(iv_str, tamano):
    iv = iv_str.encode('utf-8')
    if len(iv) < tamano:
        iv = iv + b'\x00' * (tamano - len(iv))
    elif len(iv) > tamano:
        iv = iv[:tamano]
    return iv

def cifrar_descifrar(modulo, clave, iv, texto):
    texto_bytes = texto.encode('utf-8')
    cifrador    = modulo.new(clave, modulo.MODE_CBC, iv)
    cifrado     = cifrador.encrypt(pad(texto_bytes, modulo.block_size))
    descifrador = modulo.new(clave, modulo.MODE_CBC, iv)
    descifrado  = unpad(descifrador.decrypt(cifrado), modulo.block_size).decode('utf-8')
    return cifrado, descifrado

print("=== Lab 4: Cifrado Simetrico ===")
texto  = input("Texto a cifrar : ")
key_in = input("Key base       : ")
iv_in  = input("IV base        : ")

algoritmos = [
    ("DES",     DES,  8,  8),
    ("3DES",    DES3, 24, 8),
    ("AES-256", AES,  32, 16),
]

for nombre, modulo, key_size, iv_size in algoritmos:
    print(f"\n{'─'*45}")
    print(f" {nombre}")
    print(f"{'─'*45}")
    clave = ajustar_clave(key_in, key_size)
    iv    = ajustar_iv(iv_in, iv_size)
    print(f" Key ajustada ({key_size}B) : {clave.hex()}")
    print(f" IV  ajustado ({iv_size}B)  : {iv.hex()}")
    cifrado, descifrado = cifrar_descifrar(modulo, clave, iv, texto)
    print(f"\n Texto original   : {texto}")
    print(f" Texto cifrado    : {cifrado.hex()}")
    print(f" Texto descifrado : {descifrado}")
    print(f" Verificacion     : {'OK - Coinciden' if texto == descifrado else 'ERROR - No coinciden'}")

from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import binascii
import sys

#LEER Y AJUTAR PARAMETROS

def read_input_bytes(prompt):
    message = input(prompt).strip()
    if message == "":
        return b""
    is_hex = input("¿La entrada está en hexadecimal? (s/n): ").strip()
    if is_hex == 's' or is_hex == 'S':
        # Eliminar prefijos comunes
        message_clean = message[2:] if message.startswith('0x') else message
        try:
            return binascii.unhexlify(message_clean)
        except binascii.Error:
            print("Hex inválido. Se usará la cadena tal cual en UTF-8.")
            return message.encode('utf-8')
    else:
        return message.encode('utf-8')


def adjust_key(key_bytes: bytes, required_len: int) -> bytes:
    #Ajusta la clave al tamaño adecuado
    if len(key_bytes) == required_len:
        return key_bytes
    if len(key_bytes) < required_len:
        needed = required_len - len(key_bytes)
        extra = get_random_bytes(needed)
        final = key_bytes + extra
        print(f"La clave era corta ({len(key_bytes)} bytes). Se añadieron {needed} bytes aleatorios.")
        return final
    # mayor
    print(f"La clave era larga ({len(key_bytes)} bytes). Se truncará a {required_len} bytes.")
    return key_bytes[:required_len]


def ensure_iv(IV: bytes, required_len: int) -> bytes:
    #Asegura IV y casos borde como que esté vaciío o muy corto
    if len(IV) == required_len:
        return IV
    if len(IV) == 0:
        IV_new = get_random_bytes(required_len)
        print(f"IV no entregado: se generó un IV aleatorio de {required_len} bytes.")
        return IV_new
    if len(IV) < required_len:
        print(f"IV demasiado corto ({len(IV)} bytes). Se rellenará con ceros hasta {required_len} bytes.")
        return IV + b"\x00" * (required_len - len(IV))
    # mayor
    print(f"IV demasiado largo ({len(IV)} bytes). Se truncará a {required_len} bytes.")
    return IV[:required_len]


def bytes_display_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode('utf-8')


# CIFRADO Y DESCIFRADO

def encrypt(algo:int, key:bytes, IV:bytes, plain_text:str)->(str, bytes):
    pt = plain_text.encode('utf-8')
    ciph_text:bytes = b'0x0'
    match algo:
        case 0:
            #DES
            cipher = DES.new(key, DES.MODE_CBC, IV)
            ciph_text = cipher.encrypt(pad(pt, DES.block_size))
        case 1:
            #AES
            cipher = AES.new(key, AES.MODE_CBC, IV)
            ciph_text = cipher.encrypt(pad(pt, AES.block_size))
        case 2:
            #3DES
            cipher = DES3.new(key, DES3.MODE_CBC, IV)
            ciph_text = cipher.encrypt(pad(pt, DES3.block_size))
    return base64.b64encode(ciph_text).decode('utf-8'), ciph_text


def decrypt(algo:int, key:bytes, IV:bytes, ct_bytes:bytes)-> str:
    plain_text:bytes = b''
    match algo:
        case 0:
            #DES
            cipher = DES.new(key, DES.MODE_CBC, IV)
            plain_text = unpad(cipher.decrypt(ct_bytes), DES.block_size)
        case 1:
            #AES
            cipher = AES.new(key, AES.MODE_CBC, IV)
            plain_text = unpad(cipher.decrypt(ct_bytes), AES.block_size)
        case 2:
            #3DES
            cipher = DES3.new(key, DES3.MODE_CBC, IV)
            plain_text = unpad(cipher.decrypt(ct_bytes), DES3.block_size)
    return plain_text.decode('utf-8')

# CLIENTE CONTROLADOR TERMINAL

def process_algorithm(algo, name, key_required_len, iv_required_len, encrypt_fn, decrypt_fn):
    print('\n' + '='*40)
    print(f"Algoritmo: {name}")
    kb = read_input_bytes(f"Ingrese la key para {name} (texto o hex): ")
    kb = adjust_key(kb, key_required_len)
    ivb = read_input_bytes(f"Ingrese el IV para {name} (texto o hex, tamaño {iv_required_len} bytes): ")
    ivb = ensure_iv(ivb, iv_required_len)
    print(f"Key final usada (hex): {bytes_display_hex(kb)}")
    print(f"IV final usado  (hex): {bytes_display_hex(ivb)}")
    text = input("Ingrese el texto a cifrar: ")
    ct_b64, ct_bytes = encrypt_fn(algo, kb, ivb, text)
    print(f"Texto cifrado (base64): {ct_b64}")
    # Para descifrar, uso ct_bytes
    try:
        pt = decrypt_fn(algo, kb, ivb, ct_bytes)
        print(f"Texto descifrado: {pt}")
    except Exception as e:
        print("Error al descifrar:", e)

# MAIN

def main():
    print("Programa interactivo de cifrado (DES, AES-256, 3DES) - modo CBC")
    print("Nota: Cuando se pida key/IV puede ingresar texto plano o hexadecimal.")
    print("Si la clave es corta se agregarán bytes aleatorios; si es larga se truncará.")

    algo_names = ['DES', 'AES', '3DES']
    req_IV_len = [8, 16, 8]
    req_key_len = [8, 32, 24]

    for i in range(3):
        process_algorithm(i, algo_names[i], key_required_len=req_key_len[i], iv_required_len=req_IV_len[i],
        encrypt_fn=encrypt, decrypt_fn=decrypt)
    print('\nTodas las operaciones finalizadas.')


if __name__ == '__main__': # Solo para manejar errores o desconexiones
    try:
        main()
    except KeyboardInterrupt:
        print('\nInterrumpido por usuario. Saliendo.')
        sys.exit(0)

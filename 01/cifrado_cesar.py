def cesar(texto: str, desplazamiento: int) -> str:
    resultado = []

    for ch in texto:
        if ch.isalpha():
            if ch.isupper():
                # Mayúscula → desplazamiento a la derecha
                base = ord('A')
                nuevo = (ord(ch) - base + desplazamiento) % 26 + base
                resultado.append(chr(nuevo))
            else:
                # Minúscula → desplazamiento a la izquierda
                base = ord('a')
                nuevo = (ord(ch) - base - desplazamiento) % 26 + base
                resultado.append(chr(nuevo))
        else:
            # Si no es letra, lo dejamos igual
            resultado.append(ch)

    return ''.join(resultado)


if __name__ == "__main__":
    texto = input("Ingrese el texto a cifrar: ")
    desplazamiento = int(input("Ingrese el desplazamiento: "))
    cifrado = cesar(texto, desplazamiento)
    print("Texto cifrado:", cifrado)

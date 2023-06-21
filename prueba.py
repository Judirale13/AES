def encrypt(plaintext, key):
    # Cifrar el texto
    encrypted_text_hex = hex(int(plaintext.encode().hex(), 16) ^ int(key.encode().hex(), 16))[2:]
    return encrypted_text_hex

def decrypt(ciphertext, key):
    # Desencriptar el texto
    decrypted_text_hex = hex(int(ciphertext, 16) ^ int(key.encode().hex(), 16))[2:]
    decrypted_text = bytes.fromhex(decrypted_text_hex).decode()
    return decrypted_text

while True:
    print("Seleccione una opción:")
    print("1. Encriptar texto")
    print("2. Desencriptar texto")
    print("3. Salir")

    opcion = input("Ingrese el número de la opción: ")

    if opcion == "1":
        texto = input("Ingrese el texto a encriptar: ")
        clave = input("Ingrese la clave generada: ")
        texto_cifrado = encrypt(texto, clave)
        print("Texto cifrado en hexadecimal: ", texto_cifrado)
        print()
    elif opcion == "2":
        texto_cifrado = input("Ingrese el texto cifrado en hexadecimal: ")
        clave = input("Ingrese la clave generada: ")
        texto_desencriptado = decrypt(texto_cifrado, clave)
        print("Texto desencriptado: ", texto_desencriptado)
        print()
    elif opcion == "3":
        break
    else:
        print("Opción inválida. Por favor, seleccione una opción válida.")
        print()

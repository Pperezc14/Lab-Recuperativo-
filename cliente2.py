import socket
import random
import hashlib

def generar_clave_privada():
    return random.randint(2, 100)

def generar_clave_publica(clave_privada, p, g):
    return (g ** clave_privada) % p

def generar_clave_compartida(clave_privada, clave_publica_otro, p):
    return (clave_publica_otro ** clave_privada) % p

def pad_texto(texto):
    bloque_tamaño = 16
    longitud_original = len(texto)
    relleno = bloque_tamaño - (longitud_original % bloque_tamaño)
    texto += chr(relleno) * relleno
    return texto

def quitar_relleno(texto):
    relleno = ord(texto[-1])
    return texto[:-relleno]

def cifrar_aes(texto, clave):
    texto = pad_texto(texto)
    texto_cifrado = ""
    for i in range(0, len(texto), 16):
        bloque = [ord(c) for c in texto[i:i+16]]
        for j in range(16):
            bloque[j] ^= clave[j]
        texto_cifrado += ''.join([chr(c) for c in bloque])
    return texto_cifrado

def descifrar_aes(texto_cifrado, clave):
    texto_descifrado = ""
    for i in range(0, len(texto_cifrado), 16):
        bloque = [ord(c) for c in texto_cifrado[i:i+16]]
        for j in range(16):
            bloque[j] ^= clave[j]
        texto_descifrado += ''.join([chr(c) for c in bloque])
    return quitar_relleno(texto_descifrado)

# Parámetros para Diffie-Hellman
p = 23  # Número primo para el módulo
g = 5   # Número generador

# Configuración del socket del cliente
host = '127.0.0.1'
port = 12345

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
    cliente.connect((host, port))

    # Recibir clave pública del servidor
    clave_publica_servidor = int(cliente.recv(1024).decode())

    # Lógica de Diffie-Hellman
    clave_privada_cliente = generar_clave_privada()
    clave_publica_cliente = generar_clave_publica(clave_privada_cliente, p, g)

    # Enviar clave pública al servidor
    cliente.send(str(clave_publica_cliente).encode())

    # Calcular la clave compartida
    clave_compartida_cliente = generar_clave_compartida(clave_privada_cliente, clave_publica_servidor, p)

    # Mensaje a cifrar
    mensaje_cliente = "Mensaje cifrado con AES256"

    # Calcular la clave AES a partir de la clave compartida
    clave_aes_cliente = hashlib.sha256(str(clave_compartida_cliente).encode()).digest()

    # Cifrar el mensaje con la clave AES
    mensaje_cifrado_cliente = cifrar_aes(mensaje_cliente, clave_aes_cliente)

    # Enviar el mensaje cifrado al servidor
    cliente.send(mensaje_cifrado_cliente.encode())

    # Recibir el mensaje descifrado del servidor
    mensaje_descifrado_servidor = cliente.recv(1024).decode()

    # Imprimir el mensaje descifrado y revertido
    print("Mensaje descifrado y revertido en el cliente:", mensaje_descifrado_servidor)


print("Mensaje descifrado y revertido en el cliente:", mensaje_descifrado_servidor)

# Guardar el mensaje descifrado y revertido en un archivo
with open('mensaje_descifrado.txt', 'w') as file:
    file.write(mensaje_descifrado_servidor[::1])

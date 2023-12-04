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

# Configuración del socket del servidor
host = '127.0.0.1'
port = 12345

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
    servidor.bind((host, port))
    servidor.listen()

    print(f"Servidor escuchando en {host}:{port}")

    conexion, direccion = servidor.accept()
    with conexion:
        print(f"Conexión establecida desde {direccion}")

        # Lógica de Diffie-Hellman
        clave_privada_servidor = generar_clave_privada()
        clave_publica_servidor = generar_clave_publica(clave_privada_servidor, p, g)

        # Enviar clave pública al cliente
        conexion.send(str(clave_publica_servidor).encode())

        # Recibir clave pública del cliente
        clave_publica_cliente = int(conexion.recv(1024).decode())

        # Calcular la clave compartida
        clave_compartida_servidor = generar_clave_compartida(clave_privada_servidor, clave_publica_cliente, p)

        # Recibir el mensaje cifrado del cliente
        mensaje_cifrado_cliente = conexion.recv(1024).decode()

        # Calcular la clave AES a partir de la clave compartida
        clave_aes_servidor = hashlib.sha256(str(clave_compartida_servidor).encode()).digest()

        # Descifrar el mensaje con la clave AES
        mensaje_descifrado_servidor = descifrar_aes(mensaje_cifrado_cliente, clave_aes_servidor)

        # Imprimir el mensaje descifrado invertido
        print("Mensaje descifrado y revertido en el servidor:", mensaje_descifrado_servidor[::-1])
        conexion.send(str(mensaje_descifrado_servidor).encode())


# Imprimir el mensaje descifrado invertido
print("Mensaje descifrado y revertido en el servidor:", mensaje_descifrado_servidor[::-1])


# Abrir el archivo en modo append ('a') para agregar nuevos mensajes
with open('mensajes.txt', 'w', encoding='utf-8') as file:
    # Escribir el mensaje cifrado y descifrado invertido en el archivo
    file.write(f"Mensaje cifrado del cliente:\n{mensaje_cifrado_cliente}\n\n")
    file.write(f"Mensaje descifrado y revertido del cliente:\n{mensaje_descifrado_servidor[::-1]}\n\n")

# Imprimir el mensaje cifrado y descifrado invertido
print("Mensaje cifrado en el servidor:", mensaje_cifrado_cliente)
print("Mensaje descifrado y revertido en el servidor:", mensaje_descifrado_servidor[::-1])


print("Mensaje cifrado en el servidor:", mensaje_cifrado_cliente)
print("Mensaje descifrado y revertido en el servidor:", mensaje_descifrado_servidor[::-1])

# Guardar el mensaje cifrado y descifrado invertido en un archivo
with open('mensaje_hecho.txt', 'w', encoding='utf-8') as file:
    file.write(f"Mensaje cifrado:\n{mensaje_cifrado_cliente}\n\nMensaje descifrado y revertido:\n{mensaje_descifrado_servidor[::-1]}")


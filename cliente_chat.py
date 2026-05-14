import socket
import threading
import sys
import re
import rsa

# =============================================================================
# VARIABLES GLOBALES
# =============================================================================

# Dirección IP del servidor
HOST_SERVER = ''

# Puerto de conexión TCP
PORT = 8080

# Nombre del usuario conectado
USER_NAME = ''

# Longitud máxima permitida para nombres de usuario
MAX_NAME_LENGTH = 8

# Contraseña del usuario
PASSWORD = ''

# Acción de autenticación (LOGIN o REGISTER)
AUTH_ACTION = ''


# =============================================================================
# FUNCIONES DE UTILIDAD Y CONFIGURACIÓN INICIAL
# =============================================================================

def is_valid_ip(ip):
    """
    Verifica si una cadena tiene un formato IPv4 válido.

    Parámetros:
        ip (str): Dirección IP a validar.

    Retorna:
        bool: True si la IP es válida, False en caso contrario.
    """

    # Expresión regular para formato IPv4
    regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"

    # Verifica coincidencia básica
    if re.match(regex, ip):

        parts = ip.split('.')

        try:
            # Verifica rango válido por segmento
            for part in parts:

                if not (0 <= int(part) <= 255):
                    return False

        except ValueError:
            return False

        return True

    return False


def get_config():
    """
    Solicita al usuario los datos necesarios para conectarse:

    - IP del servidor
    - Tipo de autenticación
    - Nombre de usuario
    - Contraseña
    """

    global HOST_SERVER, USER_NAME, PASSWORD, AUTH_ACTION

    # =========================================================================
    # SOLICITAR IP DEL SERVIDOR
    # =========================================================================

    while True:

        ip = input("Ingrese la IP del servidor (ej: 192.168.1.50): ")

        if is_valid_ip(ip):

            HOST_SERVER = ip
            break

        else:
            print("[ERROR] Formato de IP incorrecto. Intente de nuevo.")

    # =========================================================================
    # MENÚ DE ACCESO
    # =========================================================================

    print("\n--- MENÚ DE ACCESO ---")
    print("1. Iniciar Sesión")
    print("2. Registrarse")

    while True:

        opcion = input("Elige una opción (1 o 2): ")

        # Opción iniciar sesión
        if opcion == '1':

            AUTH_ACTION = 'LOGIN'
            break

        # Opción registrarse
        elif opcion == '2':

            AUTH_ACTION = 'REGISTER'
            break

        else:
            print("[ERROR] Opción no válida. Ingresa 1 o 2.")

    # =========================================================================
    # SOLICITAR NOMBRE DE USUARIO
    # =========================================================================

    while True:

        name = input(
            f"Ingrese su nombre de usuario "
            f"(máx. {MAX_NAME_LENGTH} caracteres, sin espacios): "
        )

        # Validaciones de nombre
        if (
            1 <= len(name) <= MAX_NAME_LENGTH
            and " " not in name
            and "|" not in name
        ):

            USER_NAME = name
            break

        else:
            print(
                f"[ERROR] Inválido. "
                f"No debe tener espacios, ni '|', "
                f"y máximo {MAX_NAME_LENGTH} caracteres."
            )

    # =========================================================================
    # SOLICITAR CONTRASEÑA
    # =========================================================================

    while True:

        pwd = input("Ingrese su contraseña (sin espacios): ")

        # Validación básica
        if len(pwd) > 0 and " " not in pwd:

            PASSWORD = pwd
            break

        else:
            print(
                "[ERROR] La contraseña no puede "
                "estar vacía ni contener espacios."
            )

    # =========================================================================
    # RESUMEN DE CONFIGURACIÓN
    # =========================================================================

    print("-" * 30)

    print(
        f"Modo: TCP | "
        f"Acción: {AUTH_ACTION} | "
        f"Usuario: {USER_NAME} | "
        f"Servidor: {HOST_SERVER}:{PORT}"
    )

    print("-" * 30)


# =============================================================================
# CLIENTE TCP (CHAT)
# =============================================================================

def tcp_receive_messages(sock, private_key):
    """
    Hilo encargado de recibir mensajes desde el servidor.

    Parámetros:
        sock (socket):
            Socket TCP conectado al servidor.

        private_key:
            Llave privada RSA utilizada para descifrar mensajes.
    """

    while True:

        try:
            # Recibe datos del servidor
            data = sock.recv(2048)

            # Si no llegan datos, el servidor cerró conexión
            if not data:

                print(
                    "\n[DESCONECTADO] "
                    "El Servidor ha cerrado la conexión. "
                    "Presiona Enter para salir."
                )

                sock.close()
                break

            # Descifra mensaje recibido
            decoded_message = rsa.decrypt(
                data,
                private_key
            ).decode('utf-8').strip()

            # ================================================================
            # MENSAJES DE ERROR DEL SERVIDOR
            # ================================================================

            if (
                decoded_message.startswith("[SERVER]: Error:")
                or decoded_message.startswith("[SERVER]: El nombre")
                or decoded_message.startswith("[SERVER]: Límite")
            ):

                print(f"\n<< {decoded_message}\n")

                sock.close()
                break

            # ================================================================
            # MENSAJES NORMALES
            # ================================================================

            else:

                print(f"\n<< {decoded_message}")

        except:
            break


def start_tcp_client():
    """
    Inicializa la conexión TCP con el servidor
    y gestiona el envío y recepción de mensajes.
    """

    # Crea socket TCP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # =====================================================================
        # CONEXIÓN AL SERVIDOR
        # =====================================================================

        print(f"Intentando conectar a {HOST_SERVER}:{PORT} (TCP)...")

        client_socket.connect((HOST_SERVER, PORT))

        # =====================================================================
        # GENERACIÓN DE LLAVES RSA
        # =====================================================================

        print("Generando llaves RSA (puede tomar unos momentos)")

        public_key, private_key = rsa.newkeys(1024)

        # =====================================================================
        # RECEPCIÓN DE LLAVE PÚBLICA DEL SERVIDOR
        # =====================================================================

        server_public_key_data = client_socket.recv(2048)

        server_public_key = rsa.PublicKey.load_pkcs1(
            server_public_key_data
        )

        # =====================================================================
        # ENVÍO DE LLAVE PÚBLICA DEL CLIENTE
        # =====================================================================

        client_socket.sendall(public_key.save_pkcs1('PEM'))

        print(
            "Intercambio de llaves RSA exitoso. "
            "Comunicación cifrada establecida."
        )

        # =====================================================================
        # ENVÍO DE CREDENCIALES CIFRADAS
        # =====================================================================

        paquete_credenciales = (
            f"{AUTH_ACTION}|{USER_NAME}|{PASSWORD}\n"
        )

        paquete_encriptado = rsa.encrypt(
            paquete_credenciales.encode('utf-8'),
            server_public_key
        )

        client_socket.sendall(paquete_encriptado)

        # =====================================================================
        # MENSAJE DE CONEXIÓN EXITOSA
        # =====================================================================

        print(
            "¡Conexión TCP exitosa! "
            "Usa /msg [usuario] [mensaje] "
            "para mensajes privados."
        )

        # =====================================================================
        # HILO DE RECEPCIÓN
        # =====================================================================

        receive_thread = threading.Thread(
            target=tcp_receive_messages,
            args=(client_socket, private_key)
        )

        receive_thread.daemon = True

        receive_thread.start()

        # =====================================================================
        # BUCLE PRINCIPAL DE ENVÍO
        # =====================================================================

        while True:

            # Entrada del usuario
            message = input("")

            # Comando de salida
            if message.lower() == 'salir':
                break

            # Preparación del mensaje
            if message.lower().startswith('/msg'):
                msg = message + '\n'
            else:
                msg = message + '\n'

            try:
                # Cifrado del mensaje
                mensaje_encriptado = rsa.encrypt(
                    msg.encode('utf-8'),
                    server_public_key
                )

                # Envío al servidor
                client_socket.sendall(mensaje_encriptado)

            except OverflowError:

                print(
                    "[ERROR] El mensaje es demasiado largo "
                    "para cifrar con RSA. Acortar mensaje xd."
                )

    # =========================================================================
    # MANEJO DE ERRORES
    # =========================================================================

    except ConnectionRefusedError:

        print(
            "Error: Conexión rechazada. "
            "Asegúrese de que el servidor esté activo."
        )

    except Exception as e:

        print(f"Error en la conexión TCP: {e}")

    # =========================================================================
    # CIERRE DE CONEXIÓN
    # =========================================================================

    finally:

        print("Cerrando conexión...")

        client_socket.close()

        sys.exit()


# =============================================================================
# PUNTO DE ENTRADA DEL PROGRAMA
# =============================================================================

if __name__ == "__main__":

    # Solicita configuración inicial
    get_config()

    # Inicia cliente TCP
    start_tcp_client()
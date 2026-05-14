import socket
import threading
import sys
import time
import re

from datetime import datetime
import admin_tools
import logging
import os
import hashlib
import rsa

# =============================================================================
# CONFIGURACIÓN GLOBAL Y ESTRUCTURAS
# =============================================================================

# Puerto donde escuchará el servidor
PORT = 8080

# Dirección IP del servidor
HOST = None

# Lista de IPs baneadas
BANNED_IPS = []

# Lista de nombres de usuario prohibidos
BANNED_USERNAMES = []

# Lista de clientes conectados
# Formato:
# (socket, username, ip, public_key)
clients = []

# Lock para sincronización entre hilos
clients_lock = threading.Lock()

# Archivo donde se almacenan usuarios registrados
ARCHIVO_USUARIOS = "usuarios.txt"

# Número máximo de clientes simultáneos
MAX_CLIENTS = 5


# =============================================================================
# CONFIGURACIÓN DE LOGGING
# =============================================================================

# Configura logs en archivo y consola
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("server_chat.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Generación de llaves RSA del servidor
logging.info("Generando llaves RSA del Servidor...")

SERVER_PUBLICKEY, SERVER_PRIVATEKEY = rsa.newkeys(1024)

logging.info("Llaves RSA generadas.")


# =============================================================================
# FUNCIONES DE UTILIDAD Y CONFIGURACIÓN INICIAL
# =============================================================================

def ip_local():
    """
    Obtiene automáticamente la IP local del equipo.

    Retorna:
        str: Dirección IP detectada.
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.connect(('192.255.255.255', 1))
        IP = s.getsockname()[0]

    except Exception:
        IP = '127.0.0.1'

    finally:
        s.close()

    return IP


def validar_ip(ip):
    """
    Verifica si una IP tiene formato IPv4 válido.

    Parámetros:
        ip (str): IP a validar.

    Retorna:
        bool: True si es válida.
    """

    regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"

    if re.match(regex, ip):

        parts = ip.split('.')

        try:
            for part in parts:

                if not (0 <= int(part) <= 255):
                    return False

        except ValueError:
            return False

        return True

    return False


def config_inicial():
    """
    Solicita y configura la IP del servidor.
    """

    global HOST

    detected_ip = ip_local()

    logging.info("-" * 30)
    logging.info(f"IP detectada automáticamente: {detected_ip}")

    while True:

        choice = input("¿Desea usar esta IP (S/N)?: ").lower()

        # Usar IP detectada
        if choice == 's':

            HOST = detected_ip
            break

        # Ingresar IP manualmente
        elif choice == 'n':

            while True:

                custom_ip = input("Ingrese la IP (ej: 192.168.1.50): ")

                if validar_ip(custom_ip):

                    HOST = custom_ip
                    break

                else:
                    print("Formato de IP incorrecto. Intente de nuevo.")

            break

        else:
            print("Opción inválida. Ingrese 's' o 'n'.")

    logging.info("-" * 30)

    logging.info(
        f"Configuración final: "
        f"{HOST}:{PORT} | "
        f"Protocolo: TCP | "
        f"Máx. Clientes: {MAX_CLIENTS}"
    )

    logging.info("-" * 30)


# =============================================================================
# SISTEMA DE AUTENTICACIÓN Y SEGURIDAD
# =============================================================================

def hashear_password(password, salt=None):
    """
    Genera un hash SHA-256 usando salt.

    Parámetros:
        password (str): Contraseña original.
        salt (str): Salt opcional.

    Retorna:
        tuple:
            (salt_generado, hash_generado)
    """

    # Genera salt aleatorio si no existe
    if salt is None:
        salt = os.urandom(8).hex()

    # Generación de hash
    hash_obj = hashlib.sha256(
        (salt + password).encode('utf-8')
    ).hexdigest()

    return salt, hash_obj


def cargar_usuarios_registrados():
    """
    Carga los usuarios registrados desde archivo.

    Retorna:
        dict:
            {
                usuario: {
                    'salt': salt,
                    'hash': hash
                }
            }
    """

    usuarios = {}

    # Si el archivo no existe
    if not os.path.exists(ARCHIVO_USUARIOS):
        return usuarios

    # Lectura del archivo
    with open(ARCHIVO_USUARIOS, 'r', encoding='utf-8') as f:

        for linea in f:

            partes = linea.strip().split(':')

            if len(partes) == 3:

                user, salt, hash_pwd = partes

                usuarios[user] = {
                    'salt': salt,
                    'hash': hash_pwd
                }

    return usuarios


def registrar_nuevo_usuario(username, password):
    """
    Registra un nuevo usuario en archivo.

    Parámetros:
        username (str): Nombre del usuario.
        password (str): Contraseña original.
    """

    salt, hash_pwd = hashear_password(password)

    with open(ARCHIVO_USUARIOS, 'a', encoding='utf-8') as f:

        f.write(f"{username}:{salt}:{hash_pwd}\n")


# =============================================================================
# FUNCIONES CENTRALES DEL CHAT
# =============================================================================

def formatear_msg(username, message):
    """
    Formatea un mensaje para mostrarlo en el chat.

    Parámetros:
        username (str): Nombre del usuario.
        message (str): Mensaje.

    Retorna:
        str: Mensaje formateado.
    """

    timestamp = datetime.now().strftime("%d.%m|%H:%M")

    return f"[{timestamp}|{username}]: {message}\n"


def verificar_nombre_usuario(username):
    """
    Verifica si un usuario ya está conectado.

    Parámetros:
        username (str): Nombre a verificar.

    Retorna:
        bool: True si ya existe.
    """

    with clients_lock:

        for sock, name, ip in clients:

            if name.lower() == username.lower():
                return True

        return False


def obneter_socket(target_name):
    """
    Obtiene el socket de un usuario específico.

    Parámetros:
        target_name (str): Usuario objetivo.

    Retorna:
        tuple:
            (socket, nombre)
    """

    with clients_lock:

        for sock, name, ip in clients:

            if name.lower() == target_name.lower():
                return sock, name

        return None, None


def broadcast(message, sender_socket=None):
    """
    Envía un mensaje a todos los clientes conectados.

    Parámetros:
        message (str): Mensaje a enviar.
        sender_socket (socket): Socket emisor.
    """

    with clients_lock:

        for client_socket, name, ip, client_publickey in clients:

            if client_socket != sender_socket:

                try:
                    msgEncriptado = rsa.encrypt(
                        message.encode('utf-8'),
                        client_publickey
                    )

                    client_socket.sendall(msgEncriptado)

                except:
                    remover_cliente(client_socket)


def mensaje_privado(sender_name, target_name, message):
    """
    Envía un mensaje privado entre usuarios.

    Parámetros:
        sender_name (str): Usuario emisor.
        target_name (str): Usuario receptor.
        message (str): Contenido.
    """

    target_data = None

    # Buscar destinatario
    with clients_lock:

        for sock, name, ip, pubkey in clients:

            if name.lower() == target_name.lower():

                target_data = (sock, name, pubkey)
                break

    sender_data = None

    # Buscar remitente
    with clients_lock:

        for sock, name, ip, pubkey in clients:

            if name.lower() == sender_name.lower():

                sender_data = (sock, name, pubkey)
                break

    # Usuario no encontrado
    if not target_data:

        if sender_data:

            sender_socket, _, sender_pubkey = sender_data

            error_msg = rsa.encrypt(
                f"[SERVER]: Usuario '{target_name}' no encontrado.\n".encode('utf-8'),
                sender_pubkey
            )

            sender_socket.sendall(error_msg)

        return

    target_socket, official_name, target_pubkey = target_data

    private_msg = formatear_msg(
        f"PRIVADO de {sender_name}",
        message
    )

    try:
        # Enviar mensaje privado
        msg_encriptado = rsa.encrypt(
            private_msg.encode('utf-8'),
            target_pubkey
        )

        target_socket.sendall(msg_encriptado)

        # Confirmación al remitente
        if sender_data:

            sender_socket, _, sender_pubkey = sender_data

            confirm_msg = rsa.encrypt(
                f"[SERVER]: Mensaje privado enviado a {official_name}.\n".encode('utf-8'),
                sender_pubkey
            )

            sender_socket.sendall(confirm_msg)

        logging.info(
            f"[PRIVADO] "
            f"{sender_name} ha enviado un mensaje a {official_name}."
        )

    except Exception as e:

        logging.error(f"Error privado: {e}")

        remover_cliente(target_socket)


def remover_cliente(client_socket):
    """
    Remueve un cliente de la lista de conectados.

    Parámetros:
        client_socket (socket): Socket a eliminar.
    """

    name_to_remove = None

    with clients_lock:

        new_clients = []

        for sock, name, ip, pubkey in clients:

            if sock != client_socket:
                new_clients.append((sock, name, ip, pubkey))

            else:
                name_to_remove = name

        clients[:] = new_clients

    # Notificación de salida
    if name_to_remove:

        logging.info(f"Cliente '{name_to_remove}' ha salido.")

        broadcast(
            formatear_msg(
                "SERVER",
                f"{name_to_remove} ha salido del chat."
            ),
            sender_socket=None
        )

    try:
        client_socket.close()

    except:
        pass


# =============================================================================
# COMANDOS ADMINISTRATIVOS
# =============================================================================

def admin_command_container(command):
    """
    Envía comandos administrativos al módulo admin_tools.
    """

    global_vars = {
        'clients': clients,
        'clients_lock': clients_lock,
        'BANNED_IPS': BANNED_IPS,
        'BANNED_USERNAMES': BANNED_USERNAMES,
        'broadcast': broadcast,
        'remover_cliente': remover_cliente,
        'formatear_msg': formatear_msg,
        'validar_ip': validar_ip
    }

    admin_tools.comandos_servidor(command, global_vars)


def iniciar_admin_consola_thread():
    """
    Hilo encargado de leer comandos administrativos.
    """

    while True:

        try:
            command = sys.stdin.readline().strip().lower()

            if command:
                admin_command_container(command)

        except EOFError:
            break

        except Exception:
            break


# =============================================================================
# MANEJO DE CLIENTES TCP
# =============================================================================

def manejo_clientes(client_socket):
    """
    Maneja toda la lógica de conexión y comunicación
    de un cliente.
    """

    client_ip, client_port = client_socket.getpeername()

    # Verificación de límite
    if len(clients) >= MAX_CLIENTS:

        logging.warning(
            f"Límite de clientes alcanzado. "
            f"Conexión rechazada: {client_ip}"
        )

        try:
            client_socket.sendall(
                f"[SERVER]: Límite de clientes "
                f"({MAX_CLIENTS}) alcanzado. "
                f"Intente más tarde.\n".encode('utf-8')
            )

            client_socket.close()

        except:
            pass

        return

    # Verificación de IP baneada
    global BANNED_IPS

    if client_ip in BANNED_IPS:

        logging.warning(
            f"Intento de conexión de IP baneada: {client_ip}"
        )

        try:
            client_socket.sendall(
                "[SERVER]: Tu IP ha sido baneada de este chat.\n".encode('utf-8')
            )

            client_socket.close()

        except:
            pass

        return

    username = "Invitado"

    try:
        # ================================================================
        # HANDSHAKE RSA
        # ================================================================

        client_socket.sendall(
            SERVER_PUBLICKEY.save_pkcs1('PEM')
        )

        client_pubkey_data = client_socket.recv(2048)

        client_pubkey = rsa.PublicKey.load_pkcs1(
            client_pubkey_data
        )

        # ================================================================
        # RECEPCIÓN DE CREDENCIALES
        # ================================================================

        paquete_data_encriptado = client_socket.recv(2048)

        if not paquete_data_encriptado:
            raise Exception("Desconexión en Handshake")

        paquete_data = rsa.decrypt(
            paquete_data_encriptado,
            SERVER_PRIVATEKEY
        ).decode('utf-8').strip()

        paquete = paquete_data.split('|')

        # Verificación de formato
        if len(paquete) != 3:

            msg_error = rsa.encrypt(
                "[SERVER]: Formato inválido.\n".encode('utf-8'),
                client_pubkey
            )

            client_socket.sendall(msg_error)

            client_socket.close()

            return

        accion, username, password = paquete

        # ================================================================
        # VALIDACIONES DE SEGURIDAD
        # ================================================================

        if accion not in ['LOGIN', 'REGISTER']:

            msg_error = rsa.encrypt(
                "[SERVER]: Error de seguridad. Acción no permitida.\n".encode('utf-8'),
                client_pubkey
            )

            client_socket.sendall(msg_error)

            client_socket.close()

            return

        if not username or len(username) > 8 or " " in username:

            logging.warning(
                f"Intento de inyección/formato inválido "
                f"en nombre de usuario desde {client_ip}"
            )

            msg_error = rsa.encrypt(
                "[SERVER]: Formato de nombre inválido.\n".encode('utf-8'),
                client_pubkey
            )

            client_socket.sendall(msg_error)

            client_socket.close()

            return

        if not password or " " in password:

            msg_error = rsa.encrypt(
                "[SERVER]: Formato de contraseña inválido.\n".encode('utf-8'),
                client_pubkey
            )

            client_socket.sendall(msg_error)

            client_socket.close()

            return

        # ================================================================
        # AUTENTICACIÓN
        # ================================================================

        usuarios_bd = cargar_usuarios_registrados()

        # ------------------------------------------------
        # REGISTRO
        # ------------------------------------------------
        if accion == 'REGISTER':

            if username in usuarios_bd:

                msg = rsa.encrypt(
                    f"[SERVER]: El usuario '{username}' ya existe.\n".encode('utf-8'),
                    client_pubkey
                )

                client_socket.sendall(msg)

                client_socket.close()

                return

            else:

                registrar_nuevo_usuario(username, password)

                logging.info(f"NUEVO REGISTRO: '{username}'")

        # ------------------------------------------------
        # LOGIN
        # ------------------------------------------------
        elif accion == 'LOGIN':

            if username not in usuarios_bd:

                msg = rsa.encrypt(
                    f"[SERVER]: El usuario '{username}' no existe.\n".encode('utf-8'),
                    client_pubkey
                )

                client_socket.sendall(msg)

                client_socket.close()

                return

            salt_guardado = usuarios_bd[username]['salt']
            hash_guardado = usuarios_bd[username]['hash']

            _, hash_ingresado = hashear_password(
                password,
                salt_guardado
            )

            if hash_guardado != hash_ingresado:

                logging.warning(f"Login fallido para '{username}'")

                msg = rsa.encrypt(
                    f"[SERVER]: Contraseña incorrecta.\n".encode('utf-8'),
                    client_pubkey
                )

                client_socket.sendall(msg)

                client_socket.close()

                return

            if usuarios_bd[username] != hashear_password(password):

                logging.warning(f"Login fallido para '{username}'")

                msg = rsa.encrypt(
                    f"[SERVER]: Contraseña incorrecta.\n".encode('utf-8'),
                    client_pubkey
                )

                client_socket.sendall(msg)

                client_socket.close()

                return

        # ================================================================
        # REGISTRO DEL CLIENTE CONECTADO
        # ================================================================

        with clients_lock:

            clients.append(
                (
                    client_socket,
                    username,
                    client_ip,
                    client_pubkey
                )
            )

        # ================================================================
        # MENSAJE DE BIENVENIDA
        # ================================================================

        welcome_msg = rsa.encrypt(
            f"[SERVER]: Bienvenido a la sala segura, {username}.\n".encode('utf-8'),
            client_pubkey
        )

        client_socket.sendall(welcome_msg)

        broadcast(
            formatear_msg(
                "SERVER",
                f"{username} se ha unido de forma segura."
            ),
            client_socket
        )

    except Exception as e:

        logging.error(f"Falla con cliente {client_ip}: {e}")

        remover_cliente(client_socket)

        return

    # =====================================================================
    # BUCLE PRINCIPAL DE MENSAJES
    # =====================================================================

    while True:

        try:
            messageDataEncriptado = client_socket.recv(2048)

            if not messageDataEncriptado:

                remover_cliente(client_socket)
                break

            # Descifrar mensaje
            message = rsa.decrypt(
                messageDataEncriptado,
                SERVER_PRIVATEKEY
            ).decode('utf-8').strip()

            # ================================================================
            # VALIDACIONES ANTI-SPAM / DoS
            # ================================================================

            if not message:
                continue

            if len(message) > 200:

                logging.warning(
                    f"Ataque DoS mitigado: "
                    f"{username} intentó enviar "
                    f"{len(message)} caracteres."
                )

                msg_aviso = rsa.encrypt(
                    "[SERVER]: Tu mensaje es demasiado largo y fue bloqueado por seguridad.\n".encode('utf-8'),
                    SERVER_PRIVATEKEY
                )

                client_socket.sendall(msg_aviso)

                continue

            # ================================================================
            # MENSAJES PRIVADOS
            # ================================================================

            if message.lower().startswith('/msg'):

                parts = message.split(' ', 2)

                if len(parts) == 3 and parts[2].strip():

                    target_name = parts[1]
                    private_content = parts[2]

                    mensaje_privado(
                        username,
                        target_name,
                        private_content
                    )

            # ================================================================
            # MENSAJES PÚBLICOS
            # ================================================================

            else:

                msgFormateado = formatear_msg(username, message)

                logging.info(
                    f"Acción: Mensaje público de '{username}'"
                )

                broadcast(msgFormateado, client_socket)

        except (socket.error, ConnectionResetError, BrokenPipeError):

            logging.warning(
                f"Desconexión abrupta de {username}."
            )

            remover_cliente(client_socket)

            break

        except Exception as e:

            logging.error(
                f"Error inesperado con {username}: {e}"
            )

            remover_cliente(client_socket)

            break


# =============================================================================
# INICIO DEL SERVIDOR
# =============================================================================

def iniciar_servidor():
    """
    Inicializa el servidor TCP.
    """

    global HOST

    # Configuración inicial
    config_inicial()

    # Creación del socket TCP
    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # Permite reutilizar el puerto
    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    try:
        # Bind del servidor
        server.bind((HOST, PORT))

        # Escuchar conexiones
        server.listen(MAX_CLIENTS)

        logging.info("SERVIDOR TCP ACTIVO")

        logging.info(f"HOST | PUERTO: {HOST}:{PORT}")

        logging.info(
            "Escriba comandos y espere el log del chat a continuación:"
        )

        logging.info("-" * 30)

        # ================================================================
        # HILO ADMINISTRATIVO
        # ================================================================

        admin_thread = threading.Thread(
            target=iniciar_admin_consola_thread,
            daemon=True
        )

        admin_thread.start()

        # ================================================================
        # BUCLE PRINCIPAL DEL SERVIDOR
        # ================================================================

        while True:

            # Espera conexiones entrantes
            client_socket, addr = server.accept()

            # Crear hilo por cliente
            client_handler = threading.Thread(
                target=manejo_clientes,
                args=(client_socket,),
                daemon=True
            )

            client_handler.start()

    except Exception as e:

        logging.critical(
            f"No se pudo iniciar el servidor TCP: {e}"
        )

        time.sleep(2)

        sys.exit()


# =============================================================================
# PUNTO DE ENTRADA DEL PROGRAMA
# =============================================================================

if __name__ == "__main__":

    iniciar_servidor()
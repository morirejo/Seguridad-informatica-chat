# admin_tools.py
"""
Módulo de herramientas administrativas para el servidor de chat.

Este archivo contiene todas las funciones relacionadas con la administración
del servidor, tales como:

- Mostrar clientes conectados.
- Expulsar usuarios.
- Banear IPs.
- Banear nombres de usuario.
- Procesar comandos administrativos desde consola.
"""

import sys

# ============================================================================
# DICCIONARIO DE COMANDOS DISPONIBLES
# ============================================================================

ADMIN_COMMANDS = {
    "comandos":         "Muestra esta lista de comandos.",
    "/list":            "Muestra [ID, Nombre, IP] de los clientes conectados.",
    "/kick [nombre]":   "Expulsa (desconecta forzosamente) a un usuario por su nombre.",
    "/banip [ip]":      "Banea permanentemente una IP para evitar futuras reconexiones.",
    "/banuser [nombre]":"Prohíbe el uso de un nombre de usuario específico.",
    "/exit":            "Cierra el servidor y desconecta a todos los clientes."
}

# ============================================================================
# FUNCIÓN: lista_de_clientes
# ============================================================================

def lista_de_clientes(clients, clients_lock):
    """
    Muestra en consola la lista de clientes actualmente conectados.

    Parámetros:
        clients (list):
            Lista de clientes conectados.
            Cada cliente contiene:
            (socket, nombre, ip, clave_publica)

        clients_lock (threading.Lock):
            Lock utilizado para acceso seguro a la lista compartida.
    """

    # Verifica si existen clientes conectados
    if not clients:
        print("No hay clientes conectados.")
        return

    # Encabezado visual
    print("\n--- Clientes Conectados ---")
    print("ID | Nombre     | IP")
    print("---|------------|----------------")

    # Uso de lock para evitar conflictos concurrentes
    with clients_lock:

        # Recorre todos los clientes conectados
        for i, (sock, name, ip, pubkey) in enumerate(clients):

            # Muestra información básica
            print(f"{i+1:<2} | {name:<10} | {ip}")

    print("---------------------------\n")


# ============================================================================
# FUNCIÓN: kick_usuario
# ============================================================================

def kick_usuario(
    target_name,
    clients,
    clients_lock,
    broadcast_func,
    remover_cliente_func,
    formatear_msg_func
):
    """
    Expulsa a un usuario conectado del servidor.

    Parámetros:
        target_name (str):
            Nombre del usuario a expulsar.

        clients (list):
            Lista de clientes conectados.

        clients_lock (Lock):
            Lock de sincronización.

        broadcast_func (function):
            Función para enviar mensajes a todos los clientes.

        remover_cliente_func (function):
            Función encargada de remover clientes.

        formatear_msg_func (function):
            Función para formatear mensajes del servidor.
    """

    target_socket = None

    # Acceso seguro a la lista compartida
    with clients_lock:

        new_clients = []
        found = False

        # Recorre todos los clientes
        for sock, name, ip, pubkey in clients:

            # Busca coincidencia de nombre
            if name.lower() == target_name.lower():
                target_socket = sock
                found = True

            else:
                new_clients.append((sock, name, ip, pubkey))

        # Actualiza la lista si se encontró
        if found:
            clients[:] = new_clients

    # Si se encontró el socket del usuario
    if target_socket:

        print(f"[ADMIN] Expulsando a {target_name}...")

        try:
            # Cierra conexión
            target_socket.close()

            # Notifica al resto del chat
            broadcast_func(
                formatear_msg_func(
                    "SERVER",
                    f"{target_name} ha sido expulsado por un administrador."
                ),
                sender_socket=None
            )

        except:
            pass

    else:
        print(f"Usuario '{target_name}' no encontrado.")


# ============================================================================
# FUNCIÓN: banear_ip
# ============================================================================

def banear_ip(
    target_ip,
    clients,
    clients_lock,
    BANNED_IPS,
    broadcast_func,
    remover_cliente_func,
    formatear_msg_func,
    validar_ip_func
):
    """
    Banea permanentemente una dirección IP.

    Parámetros:
        target_ip (str):
            IP que será baneada.

        clients (list):
            Lista de clientes conectados.

        clients_lock (Lock):
            Lock de sincronización.

        BANNED_IPS (list):
            Lista global de IPs baneadas.

        broadcast_func (function):
            Función para enviar mensajes globales.

        remover_cliente_func (function):
            Función para remover clientes.

        formatear_msg_func (function):
            Función de formato de mensajes.

        validar_ip_func (function):
            Función que valida el formato de la IP.
    """

    # Verifica que la IP sea válida
    if not validar_ip_func(target_ip):
        print(f"IP '{target_ip}' no es válida.")
        return

    # Verifica si ya está baneada
    if target_ip not in BANNED_IPS:

        BANNED_IPS.append(target_ip)

        print(
            f"[ADMIN] IP {target_ip} baneada permanentemente. "
            f"IPs baneadas: {len(BANNED_IPS)}"
        )

    else:
        print(f"IP {target_ip} ya está baneada.")
        return

    # Separa clientes expulsados y válidos
    with clients_lock:

        clients_to_kick = []
        new_clients = []

        for sock, name, ip, pubkey in clients:

            # Si coincide la IP → expulsar
            if ip == target_ip:
                clients_to_kick.append((sock, name))

            else:
                new_clients.append((sock, name, ip, pubkey))

        # Actualiza lista de clientes
        clients[:] = new_clients

    # Expulsar usuarios afectados
    for sock, name in clients_to_kick:

        print(f"[ADMIN] Expulsando a {name} ({target_ip}) por baneo de IP.")

        try:
            sock.close()

            broadcast_func(
                formatear_msg_func(
                    "SERVER",
                    f"{name} ha sido baneado permanentemente por IP."
                ),
                sender_socket=None
            )

        except:
            pass


# ============================================================================
# FUNCIÓN: banear_nombre_usuario
# ============================================================================

def banear_nombre_usuario(
    target_name,
    clients,
    clients_lock,
    BANNED_USERNAMES,
    broadcast_func,
    remover_cliente_func,
    formatear_msg_func
):
    """
    Prohíbe permanentemente el uso de un nombre de usuario.

    Parámetros:
        target_name (str):
            Nombre a prohibir.

        clients (list):
            Lista de clientes conectados.

        clients_lock (Lock):
            Lock de sincronización.

        BANNED_USERNAMES (list):
            Lista global de nombres prohibidos.

        broadcast_func (function):
            Función para broadcast.

        remover_cliente_func (function):
            Función para remover clientes.

        formatear_msg_func (function):
            Función para formatear mensajes.
    """

    # Verifica nombre vacío
    if not target_name:
        print("El nombre de usuario no puede estar vacío.")
        return

    lower_target_name = target_name.lower()

    # Verifica si ya está prohibido
    if lower_target_name not in [n.lower() for n in BANNED_USERNAMES]:

        BANNED_USERNAMES.append(target_name)

        print(
            f"[ADMIN] Nombre prohibido: '{target_name}'. "
            f"Total prohibidos: {len(BANNED_USERNAMES)}"
        )

    else:
        print(f"[ADMIN] El nombre '{target_name}' ya está prohibido.")
        return

    target_socket = None

    # Recorre clientes conectados
    with clients_lock:

        new_clients = []
        found = False

        for sock, name, ip, pubkey in clients:

            # Si coincide → expulsar
            if name.lower() == lower_target_name:
                target_socket = sock
                found = True

            else:
                new_clients.append((sock, name, ip, pubkey))

        # Actualiza lista
        if found:
            clients[:] = new_clients

    # Expulsar usuario
    if target_socket:

        print(f"[ADMIN] Expulsando a {target_name} por baneo de nombre.")

        try:
            target_socket.close()

            broadcast_func(
                formatear_msg_func(
                    "SERVER",
                    f"El nombre '{target_name}' ha sido prohibido."
                ),
                sender_socket=None
            )

        except:
            pass


# ============================================================================
# FUNCIÓN: comandos_servidor
# ============================================================================

def comandos_servidor(command, global_vars):
    """
    Procesa y ejecuta comandos administrativos ingresados desde consola.

    Parámetros:
        command (str):
            Comando ingresado por el administrador.

        global_vars (dict):
            Diccionario con referencias globales del servidor.
    """

    # Obtiene referencias globales
    clients = global_vars['clients']
    clients_lock = global_vars['clients_lock']
    BANNED_IPS = global_vars['BANNED_IPS']
    BANNED_USERNAMES = global_vars['BANNED_USERNAMES']
    broadcast_func = global_vars['broadcast']
    remover_cliente_func = global_vars['remover_cliente']
    formatear_msg_func = global_vars['formatear_msg']
    validar_ip_func = global_vars['validar_ip']

    # Verifica comando vacío
    if not command:
        return

    # Divide comando en partes
    parts = command.split()
    cmd = parts[0]

    # ==========================================================
    # COMANDO: comandos
    # ==========================================================
    if cmd == 'comandos' or cmd == '/comandos':

        print("\nComandos Disponibles ---")

        for command, desc in ADMIN_COMMANDS.items():
            print(f"{command:<15} - {desc}")

        print("--------------------------------------------\n")

    # ==========================================================
    # COMANDO: /list
    # ==========================================================
    elif cmd == '/list':

        lista_de_clientes(clients, clients_lock)

    # ==========================================================
    # COMANDO: /kick
    # ==========================================================
    elif cmd == '/kick' and len(parts) >= 2:

        kick_usuario(
            parts[1],
            clients,
            clients_lock,
            broadcast_func,
            remover_cliente_func,
            formatear_msg_func
        )

    # ==========================================================
    # COMANDO: /banip
    # ==========================================================
    elif cmd == '/banip' and len(parts) >= 2:

        banear_ip(
            parts[1],
            clients,
            clients_lock,
            BANNED_IPS,
            broadcast_func,
            remover_cliente_func,
            formatear_msg_func,
            validar_ip_func
        )

    # ==========================================================
    # COMANDO: /banuser
    # ==========================================================
    elif cmd == '/banuser' and len(parts) >= 2:

        banear_nombre_usuario(
            parts[1],
            clients,
            clients_lock,
            BANNED_USERNAMES,
            broadcast_func,
            remover_cliente_func,
            formatear_msg_func
        )

    # ==========================================================
    # COMANDO: /exit
    # ==========================================================
    elif cmd == '/exit':

        print("Cerrando servidor y procesos...")

        import os
        os._exit(0)

    # ==========================================================
    # COMANDO DESCONOCIDO
    # ==========================================================
    else:

        print(f"Comando no reconocido '{command}'. Use 'comandos'.")
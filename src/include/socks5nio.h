#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H

#include "selector.h"

/**
 * @brief Handler para aceptar nuevas conexiones entrantes en el socket pasivo.
 * * Esta función debe ser asignada al campo .handle_read del fd_handler
 * asociado al socket servidor (listener).
 * * Se encarga de:
 * 1. Hacer accept() de la nueva conexión.
 * 2. Inicializar las estructuras de datos de la sesión (buffers, máquinas de estado).
 * 3. Registrar el nuevo socket cliente en el selector.
 */
void socksv5_passive_accept(struct selector_key *key);

/**
 * @brief Libera recursos globales del módulo (si los hubiera).
 * Útil para limpiar memoria al finalizar el servidor.
 */
void socksv5_pool_destroy(void);

#endif // SOCKS5NIO_H
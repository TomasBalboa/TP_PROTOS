#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "selector.h"
#include "buffer.h"
#include "stm.h"

// ============================================================================
// CONSTANTES DEL PROTOCOLO SOCKS5 - RFC1928
// ============================================================================

#define SOCKS5_VERSION 0x05

// Métodos de autenticación
enum socks5_auth_method {
    SOCKS5_AUTH_NO_AUTH       = 0x00,  // Sin autenticación
    SOCKS5_AUTH_GSSAPI        = 0x01,  // GSSAPI
    SOCKS5_AUTH_USER_PASS     = 0x02,  // Usuario/Contraseña (RFC1929)
    SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF   // Ningún método aceptable
};

// Comandos
enum socks5_cmd {
    SOCKS5_CMD_CONNECT        = 0x01,  // CONNECT
    SOCKS5_CMD_BIND           = 0x02,  // BIND (no implementado)
    SOCKS5_CMD_UDP_ASSOCIATE  = 0x03   // UDP ASSOCIATE (no implementado)
};

// Tipos de dirección
enum socks5_addr_type {
    SOCKS5_ADDR_TYPE_IPV4     = 0x01,  // IPv4
    SOCKS5_ADDR_TYPE_DOMAIN   = 0x03,  // Nombre de dominio
    SOCKS5_ADDR_TYPE_IPV6     = 0x04   // IPv6
};

// Códigos de respuesta (reply)
enum socks5_reply {
    SOCKS5_REPLY_SUCCESS                = 0x00,
    SOCKS5_REPLY_GENERAL_FAILURE        = 0x01,
    SOCKS5_REPLY_CONNECTION_NOT_ALLOWED = 0x02,
    SOCKS5_REPLY_NETWORK_UNREACHABLE    = 0x03,
    SOCKS5_REPLY_HOST_UNREACHABLE       = 0x04,
    SOCKS5_REPLY_CONNECTION_REFUSED     = 0x05,
    SOCKS5_REPLY_TTL_EXPIRED            = 0x06,
    SOCKS5_REPLY_CMD_NOT_SUPPORTED      = 0x07,
    SOCKS5_REPLY_ADDR_TYPE_NOT_SUPPORTED= 0x08
};

// ============================================================================
// CONSTANTES AUTENTICACIÓN - RFC1929
// ============================================================================

#define SOCKS5_AUTH_VERSION 0x01

enum socks5_auth_status {
    SOCKS5_AUTH_STATUS_SUCCESS = 0x00,
    SOCKS5_AUTH_STATUS_FAILURE = 0x01
};

// ============================================================================
// LÍMITES
// ============================================================================

#define MAX_AUTH_METHODS 255
#define MAX_USERNAME_LEN 255
#define MAX_PASSWORD_LEN 255
#define MAX_DOMAIN_LEN   255

// ============================================================================
// FUNCIONES PÚBLICAS
// ============================================================================

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

void socksv5_close(struct selector_key *key);

#endif // SOCKS5NIO_H

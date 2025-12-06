#ifndef MGMT_AUTH_H
#define MGMT_AUTH_H

#include "../include/selector.h"
#include "../include/auth_parser.h"
#include "../include/buffer.h"

/**
 * Módulo de autenticación para el protocolo de administración.
 * 
 * IMPORTANTE: Este módulo REUTILIZA el parser de autenticación SOCKS5 (auth_parser.h)
 * ya que ambos protocolos siguen RFC 1929 con el mismo formato:
 * - Request: [VER:1][ULEN:1][USERNAME:N][PLEN:1][PASSWORD:M]
 * - Response: [VER:1][STATUS:1]
 * 
 * Implementa una máquina de estados no bloqueante que maneja:
 * - MANAGEMENT_AUTH_READ: Lee y parsea credenciales
 * - MANAGEMENT_AUTH_WRITE: Envía respuesta de autenticación
 * 
 * Estados definidos en managment.h:
 * - MANAGMENT_AUTH_READ
 * - MANAGMENT_AUTH_WRITE
 * - MANAGMENT_REQUEST_READ (estado siguiente tras auth exitosa)
 * - MANAGMENT_ERROR
 */

// Forward declaration de la estructura del cliente de management
struct mgmt_client_data;

/**
 * Inicializa el estado de autenticación cuando se entra a MANAGEMENT_AUTH_READ.
 * Llamada automáticamente por la FSM mediante on_arrival.
 */
void mgmt_auth_init(const unsigned state, struct selector_key *key);

/**
 * Handler de lectura para el estado MANAGEMENT_AUTH_READ.
 * Lee datos del socket, los parsea con auth_parser (compartido con SOCKS5),
 * valida las credenciales y prepara la respuesta.
 * 
 * Retorna:
 * - MANAGEMENT_AUTH_WRITE: Si se parseó y validó correctamente
 * - MANAGEMENT_ERROR: Si hubo error de I/O, parsing o autenticación
 */
unsigned mgmt_auth_read(struct selector_key *key);

/**
 * Handler de escritura para el estado MANAGEMENT_AUTH_WRITE.
 * Envía la respuesta de autenticación al cliente.
 * 
 * Retorna:
 * - MANAGEMENT_REQUEST_READ: Si se envió correctamente y el usuario está autenticado
 * - MANAGEMENT_ERROR: Si hubo error de I/O o el usuario no está autenticado
 */
unsigned mgmt_auth_write(struct selector_key *key);

/**
 * Valida las credenciales del usuario contra args.users[].
 * Usa el módulo compartido user_validation para validación centralizada.
 * 
 * @param username Usuario a validar
 * @param password Contraseña a validar
 * @param is_admin Puntero donde se guardará si el usuario es admin (puede ser NULL)
 * @return true si las credenciales son válidas, false en caso contrario
 */
bool try_to_authenticate(const char *username, const char *password, bool *is_admin);

#endif // MGMT_AUTH_H

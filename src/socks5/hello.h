#ifndef HELLO_H_
#define HELLO_H_

#include <stdint.h>
#include <stdbool.h>
#include "socks5.h"
#include "buffer.h"

/**
 * hello.h - Parser del mensaje de saludo inicial SOCKS5
 * 
 * Cliente envía:
 *   +----+----------+----------+
 *   |VER | NMETHODS | METHODS  |
 *   +----+----------+----------+
 *   | 1  |    1     | 1 to 255 |
 *   +----+----------+----------+
 * 
 * Servidor responde:
 *   +----+--------+
 *   |VER | METHOD |
 *   +----+--------+
 *   | 1  |   1    |
 *   +----+--------+
 */

// ============================================================================
// PARSER DEL HELLO
// ============================================================================

enum hello_state {
    HELLO_VERSION,
    HELLO_NMETHODS,
    HELLO_METHODS,
    HELLO_DONE,
    HELLO_ERROR
};

struct hello_parser {
    enum hello_state state;
    uint8_t nmethods;
    uint8_t methods_read;
    uint8_t methods[MAX_AUTH_METHODS];
};

/** Inicializa el parser */
void hello_parser_init(struct hello_parser *p);

/**
 * Parsea el mensaje hello del cliente.
 * Retorna true si está completo, false si necesita más datos.
 * En caso de error, state será HELLO_ERROR.
 */
bool hello_parser_parse(struct hello_parser *p, buffer *buf);

/**
 * Selecciona un método de autenticación de los ofrecidos por el cliente.
 * Retorna el método seleccionado o SOCKS5_AUTH_NO_ACCEPTABLE si ninguno es válido.
 */
uint8_t hello_select_auth_method(struct hello_parser *p, bool auth_required);

/**
 * Escribe la respuesta del hello en el buffer.
 * Retorna true si se escribió completo, false si no hay espacio.
 */
bool hello_write_response(buffer *buf, uint8_t method);

#endif // HELLO_H_

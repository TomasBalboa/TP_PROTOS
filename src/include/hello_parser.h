#ifndef HELLO_PARSER_H_
#define HELLO_PARSER_H_

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"
#include "socks5nio.h"

/**
 * hello.h - Parser del mensaje inicial (handshake) de SOCKS5
 * 
 * Cliente envía:
 *   +-----+----------+----------+
 *   | VER | NMETHODS | METHODS  |
 *   +-----+----------+----------+
 *   |  1  |    1     | 1 to 255 |
 *   +-----+----------+----------+
 * 
 * Servidor responde:
 *   +-----+--------+
 *   | VER | METHOD |
 *   +-----+--------+
 *   |  1  |   1    |
 *   +-----+--------+
 */

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
    uint8_t methods[255];
};

/** Inicializa el parser */
void hello_parser_init(struct hello_parser *p);

/** Libera recursos del parser (por ahora no hace nada) */
void hello_parser_close(struct hello_parser *p);

/**
 * Consume bytes del buffer y actualiza el parser.
 * Retorna el estado actual del parser.
 */
enum hello_state hello_consume(buffer *buf, struct hello_parser *p, bool *errored);

/**
 * Alimenta el parser con un byte.
 * Retorna el estado actual del parser.
 */
enum hello_state hello_parser_feed(struct hello_parser *p, uint8_t byte);

/** Verifica si el parser terminó exitosamente */
bool hello_is_done(enum hello_state state, bool *errored);

/** Verifica si hubo error */
bool hello_has_error(enum hello_state state);

/**
 * Selecciona el mejor método de autenticación disponible.
 * Retorna 0xFF si ninguno es aceptable.
 */
uint8_t hello_select_auth_method(struct hello_parser *p, 
                                  bool no_auth_enabled, 
                                  bool user_pass_enabled);

/**
 * Escribe la respuesta del hello en un buffer.
 * Retorna -1 en caso de error, 0 en caso de éxito.
 */
int hello_marshall(buffer *buf, uint8_t method);

/**
 * Escribe la respuesta del hello en un buffer (versión alternativa).
 * Retorna la cantidad de bytes escritos (siempre 2).
 */
int hello_write_response(uint8_t *buffer, uint8_t method);

#endif

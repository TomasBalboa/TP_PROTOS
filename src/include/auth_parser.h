#ifndef AUTH_PARSER_H_
#define AUTH_PARSER_H_

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"
#include "socks5nio.h"

enum auth_state {
    AUTH_VERSION,
    AUTH_USERNAME_LEN,
    AUTH_USERNAME,
    AUTH_PASSWORD_LEN,
    AUTH_PASSWORD,
    AUTH_DONE,
    AUTH_ERROR
};

struct auth_parser {
    enum auth_state state;

    uint8_t username_len;
    uint8_t username_read;
    char username[256];

    uint8_t password_len;
    uint8_t password_read;
    char password[256];
};

/** Inicializa el parser */
void auth_parser_init(struct auth_parser *p);

/** Libera recursos del parser */
void auth_parser_close(struct auth_parser *p);

/**
 * Consume bytes del buffer y actualiza el parser.
 * Retorna el estado actual del parser.
 */
enum auth_state auth_consume(buffer *buf, struct auth_parser *p, bool *errored);

/** Verifica si el parser terminó exitosamente */
bool auth_is_done(enum auth_state state);

/** Verifica si hubo error */
bool auth_has_error(enum auth_state state);

/**
 * Escribe la respuesta de autenticación en un buffer.
 * success: true para éxito (0x00), false para error (0xFF)
 * Retorna -1 en error, 0 en éxito.
 */
int auth_marshall_response(buffer *buf, bool success);

#endif

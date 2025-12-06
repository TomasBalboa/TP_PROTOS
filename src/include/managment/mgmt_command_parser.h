#ifndef MGMT_COMMAND_PARSER_H
#define MGMT_COMMAND_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

/* Versión del protocolo de management */
#define MGMT_VERSION 0x01

/* Máximo de argumentos y longitud de cada string de argumento */
#define MGMT_MAX_ARGS        3
#define MGMT_MAX_STRING_LEN  0xFF

typedef enum {
    MGMT_ADD_USER = 0,
    MGMT_DELETE_USER,
    MGMT_LIST_USERS,
    MGMT_STATS
} mgmt_command;

typedef enum {
    MGMT_PARSER_VERSION = 0,
    MGMT_PARSER_COMMAND,
    MGMT_PARSER_LEN,
    MGMT_PARSER_PAYLOAD,
    MGMT_PARSER_DONE,
    MGMT_PARSER_ERROR,
} mgmt_parser_state;

typedef enum {
    MGMT_STATUS_OK = 0,
    MGMT_STATUS_FORBIDDEN,
    MGMT_STATUS_INVALID_VERSION,
    MGMT_STATUS_INVALID_COMMAND,
    MGMT_STATUS_INVALID_ARGS,
    MGMT_STATUS_INVALID_LENGTH,
    MGMT_STATUS_SERVER_ERROR,
} mgmt_status;

typedef struct mgmt_command_parser {
    mgmt_parser_state state;
    mgmt_command      command;
    mgmt_status       status;

    uint8_t  args_count;                 /* cantidad de argumentos leídos */
    uint8_t  expected_args;              /* argumentos esperados (según comando) */

    uint8_t  remaining;                  /* bytes de payload que faltan leer */
    uint8_t  current_len;                /* longitud del argumento actual */

    /* args[i] es un string null-terminated con el i‑ésimo argumento */
    uint8_t  args[MGMT_MAX_ARGS][MGMT_MAX_STRING_LEN + 1];
} mgmt_command_parser;

void mgmt_command_parser_init(mgmt_command_parser *p);

mgmt_parser_state mgmt_command_parser_parse(mgmt_command_parser *p, buffer *buf);

bool mgmt_command_parser_is_done(const mgmt_command_parser *p);

bool mgmt_command_parser_has_error(const mgmt_command_parser *p);

bool mgmt_command_parser_build_response(const mgmt_command_parser *p,
                                        buffer *buf,
                                        mgmt_status status,
                                        const char *msg);

#endif // MGMT_COMMAND_PARSER_H

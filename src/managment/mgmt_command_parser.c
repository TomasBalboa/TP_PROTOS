#include "../include/managment/mgmt_command_parser.h"
#include <string.h>

#define ARG_DELIM ':'  /* separador entre argumentos */

// Cantidad esperada de argumentos por comando
static uint8_t expected_args_for(mgmt_command cmd) {
    switch (cmd) {
        case MGMT_ADD_USER:    return 2;
        case MGMT_DELETE_USER: return 1;
        case MGMT_LIST_USERS:  return 0;
        case MGMT_STATS:       return 0;
        default:               return 0;
    }
}

static void set_error(mgmt_command_parser *p, mgmt_status st) {
    p->status = st;
    p->state  = MGMT_PARSER_ERROR;
}

void mgmt_command_parser_init(mgmt_command_parser *p) {
    if (p == NULL) {
        return;
    }

    memset(p, 0, sizeof(*p));
    p->state = MGMT_PARSER_VERSION;
}


mgmt_parser_state mgmt_command_parser_parse(mgmt_command_parser *p, buffer *buf) {
    if (p == NULL) {
        return MGMT_PARSER_ERROR;
    }

    while (buffer_can_read(buf) && !mgmt_command_parser_is_done(p)) {
        uint8_t c = buffer_read(buf);

        switch (p->state) {
        case MGMT_PARSER_VERSION:
            if (c != MGMT_VERSION) {
                set_error(p, MGMT_STATUS_INVALID_VERSION);
            } else {
                p->state = MGMT_PARSER_COMMAND;
            }
            break;

        case MGMT_PARSER_COMMAND:
            p->command = (mgmt_command)c;
            if (p->command < MGMT_ADD_USER || p->command > MGMT_STATS) {
                set_error(p, MGMT_STATUS_INVALID_COMMAND);
            } else {
                p->expected_args = expected_args_for(p->command);
                p->state = MGMT_PARSER_LEN;
            }
            break;

        case MGMT_PARSER_LEN:
            // longitud total del payload
            if (c > MGMT_MAX_STRING_LEN) {
                set_error(p, MGMT_STATUS_INVALID_LENGTH);
            } else {
                p->remaining = c;

                // Sin payload y sin args esperados → terminado
                if (p->remaining == 0 && p->expected_args == 0) {
                    p->status = MGMT_STATUS_OK;
                    p->state  = MGMT_PARSER_DONE;
                } else {
                    p->state = MGMT_PARSER_PAYLOAD;
                }
            }
            break;

        case MGMT_PARSER_PAYLOAD:
            if (p->remaining == 0) {
                // No debería pasar, pero por las dudas
                set_error(p, MGMT_STATUS_INVALID_LENGTH);
                break;
            }

            if (c == ARG_DELIM) {
                // Terminó un argumento
                if (p->current_len == 0) {
                    // Dos ':' seguidos o inicio con ':' → arg vacío
                    set_error(p, MGMT_STATUS_INVALID_ARGS);
                    break;
                }
                if (p->args_count >= MGMT_MAX_ARGS) {
                    set_error(p, MGMT_STATUS_INVALID_ARGS);
                    break;
                }
                p->args[p->args_count][p->current_len] = '\0';
                p->args_count++;
                p->current_len = 0;
            } else {
                // Acumular en el argumento actual
                if (p->current_len >= MGMT_MAX_STRING_LEN) {
                    set_error(p, MGMT_STATUS_INVALID_ARGS);
                    break;
                }
                p->args[p->args_count][p->current_len++] = c;
            }

            p->remaining--;

            if (p->remaining == 0) {
                // Se terminó el payload: cerrar último argumento si tiene datos
                if (p->current_len > 0) {
                    if (p->args_count >= MGMT_MAX_ARGS) {
                        set_error(p, MGMT_STATUS_INVALID_ARGS);
                        break;
                    }
                    p->args[p->args_count][p->current_len] = '\0';
                    p->args_count++;
                    p->current_len = 0;
                }

                // Validar cantidad de args
                if (p->args_count != p->expected_args) {
                    set_error(p, MGMT_STATUS_INVALID_ARGS);
                } else {
                    p->status = MGMT_STATUS_OK;
                    p->state  = MGMT_PARSER_DONE;
                }
            }
            break;

        case MGMT_PARSER_DONE:
        case MGMT_PARSER_ERROR:
            // Nada más que hacer; dejamos bytes extra en el buffer
            return p->state;
        }
    }

    return p->state;
}

bool mgmt_command_parser_is_done(const mgmt_command_parser *p) {
    return p != NULL &&
           (p->state == MGMT_PARSER_DONE || p->state == MGMT_PARSER_ERROR);
}

bool mgmt_command_parser_has_error(const mgmt_command_parser *p) {
    return p != NULL && p->state == MGMT_PARSER_ERROR;
}

bool mgmt_command_parser_build_response(const mgmt_command_parser *p,
                                        buffer *buf,
                                        mgmt_status status,
                                        const char *msg) {
    if (p == NULL || buf == NULL) {
        return false;
    }

    // versión
    if (!buffer_can_write(buf)) return false;
    buffer_write(buf, MGMT_VERSION);

    // status
    if (!buffer_can_write(buf)) return false;
    buffer_write(buf, (uint8_t)status);

    // mensaje opcional (con '\0' final)
    if (msg != NULL) {
        size_t len = strlen(msg) + 1;
        for (size_t i = 0; i < len; i++) {
            if (!buffer_can_write(buf)) return false;
            buffer_write(buf, (uint8_t)msg[i]);
        }
    }

    return true;
}

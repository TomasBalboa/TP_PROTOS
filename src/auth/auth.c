#include "socks5_internal.h"
#include "logging.h"
#include <stdio.h>
#include "buffer.h"
#include "stm.h"
#include "netutils.h"
#include "auth.h"
#include "auth_parser.h"
#include <string.h>
#include <errno.h>
// Forward declaration
static unsigned auth_process(struct selector_key *key, const struct auth_st *d);

void auth_read_init(const unsigned state, struct selector_key *key) {
    
    struct auth_st *d = &ATTACHMENT(key)->client.auth;
    (void)state;

    logf(LOG_DEBUG, "[AUTH] auth_read_init fd=%d", key->fd);

    d->rb = &(ATTACHMENT(key)->client_buffer);
    d->wb = &(ATTACHMENT(key)->origin_buffer);
    auth_parser_init(&d->parser);
}

unsigned auth_read(struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;
    unsigned ret = AUTH_READ;
    bool error = false;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        logf(LOG_DEBUG, "[AUTH] auth_read fd=%d read=%zd bytes", key->fd, n);
        buffer_write_adv(d->rb, n);
        enum auth_state st = auth_consume(d->rb, &d->parser, &error);
        if (auth_is_done(st)) {
            logf(LOG_DEBUG, "[AUTH] parser done for fd=%d state=%d error=%d", key->fd, st, error);

            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = auth_process(key, d);
            } else {
                ret = ERROR;
            }
        }
    } else if (n == 0) {
        /* Peer performed orderly shutdown */
        logf(LOG_WARNING, "[AUTH] auth_read fd=%d peer closed connection (recv=0)", key->fd);
        ret = ERROR;
    } else {
        /* n == -1 -> error */
        logf(LOG_ERROR, "[AUTH] auth_read fd=%d recv error: %s (%d)", key->fd, strerror(errno), errno);
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

void auth_read_close(const unsigned state, struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;
    (void)state;
    logf(LOG_DEBUG, "[AUTH] auth_read_close fd=%d", key->fd);
    auth_parser_close(&d->parser);
}

unsigned auth_write(struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;
    unsigned ret = AUTH_WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_read_ptr(d->wb, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n == -1) {
        ret = ERROR;
    } else {
        logf(LOG_DEBUG, "[AUTH] auth_write fd=%d wrote=%zd bytes", key->fd, n);
        buffer_read_adv(d->wb, n);
        if (!buffer_can_read(d->wb)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
                ret = REQUEST_READ;  // Pasar al siguiente estado
            } else {
                ret = ERROR;
            }
        }
    }

    return ret;
}

/**
 * Valida las credenciales y prepara la respuesta.
 * TODO: Integrar con base de datos de usuarios.
 */

static unsigned auth_process(struct selector_key *key, const struct auth_st *d) {

    
    bool auth_ok = false;

        /* Log username but DO NOT print password in logs */
        logf(LOG_INFO, "[AUTH] auth_process fd=%d user='%s'", key->fd, d->parser.username);

    // EJEMPLO SIMPLE: Permitir cualquier usuario/password
    // REEMPLAZAR con lógica real
    if (strlen(d->parser.username) > 0 && strlen(d->parser.password) > 0) {
        auth_ok = true;  // TODO: Validar credenciales reales
    }
    
    // Escribir respuesta
    if (auth_marshall_response((buffer *)d->wb, auth_ok) == -1) {
        return ERROR;
    }
    
    if (auth_ok) {
        // Guardar username en client_info para logging/estadísticas
        strncpy(ATTACHMENT(key)->username, d->parser.username, 
                sizeof(ATTACHMENT(key)->username) - 1);
        ATTACHMENT(key)->username[sizeof(ATTACHMENT(key)->username) - 1] = '\0';
        return AUTH_WRITE;
    } else {
        return ERROR;  // Rechazar conexión
    }
}

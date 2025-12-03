#include "socks5_internal.h"
#include "buffer.h"
#include "stm.h"
#include "netutils.h"
#include "hello.h"
#include "hello_parser.h"

// Handlers de estado HELLO trasladados desde socks5nio.c

void hello_read_init(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    (void)state;

    d->rb     = &(ATTACHMENT(key)->client_buffer);
    d->wb     = &(ATTACHMENT(key)->origin_buffer);
    d->method = SOCKS5_AUTH_NO_ACCEPTABLE;
    hello_parser_init(&d->parser);
}


static unsigned hello_process(struct selector_key *key, const struct hello_st* d) {
    unsigned ret = HELLO_WRITE;
    uint8_t method = SOCKS5_AUTH_NO_ACCEPTABLE;

    // Preferencia 1: No auth
    for (uint8_t i = 0; i < d->parser.nmethods; i++) {
        if (d->parser.methods[i] == SOCKS5_AUTH_NO_AUTH) {
            method = SOCKS5_AUTH_NO_AUTH;
            break;
        }
    }

    // Preferencia 2: User/Pass si NO_AUTH no está disponible
    if (method == SOCKS5_AUTH_NO_ACCEPTABLE) {
        for (uint8_t i = 0; i < d->parser.nmethods; i++) {
            if (d->parser.methods[i] == SOCKS5_AUTH_USER_PASS) {
                method = SOCKS5_AUTH_USER_PASS;
                break;
            }
        }
    }

    if (method == SOCKS5_AUTH_NO_ACCEPTABLE) {
        ret = ERROR;
    } else if (-1 == hello_marshall(d->wb, method)) {
        ret = ERROR;
    } else {
        // Guardar método seleccionado para uso en hello_write()
        ATTACHMENT(key)->selected_method = method;
    }

    return ret;
}
unsigned hello_read(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned  ret      = HELLO_READ;
    bool      error    = false;
    uint8_t  *ptr;
    size_t    count;
    ssize_t   n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n > 0) {
        buffer_write_adv(d->rb, n);
        const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
        if(hello_is_done(st, 0)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = hello_process(key, d);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

void hello_read_close(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    (void)state;
    hello_parser_close(&d->parser);
}

unsigned hello_write(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    struct client_info *client = ATTACHMENT(key);
    unsigned ret = HELLO_WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_read_ptr(d->wb, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if(n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(d->wb, n);
        if(!buffer_can_read(d->wb)) {
            // DECISIÓN: ¿Autenticación requerida?
            uint8_t method = client->selected_method;
            
            if(method == SOCKS5_AUTH_USER_PASS) {
                // Necesita autenticación
                if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
                    ret = AUTH_READ;  // <-- CAMBIO: Ir a AUTH_READ
                } else {
                    ret = ERROR;
                }
            } else if(method == SOCKS5_AUTH_NO_AUTH) {
                // Sin autenticación
                if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
                    ret = REQUEST_READ;  // <-- CAMBIO: Ir a REQUEST_READ
                } else {
                    ret = ERROR;
                }
            } else {
                ret = ERROR;
            }
        }
    }

    return ret;
}
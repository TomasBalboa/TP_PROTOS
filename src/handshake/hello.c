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

static unsigned hello_process(const struct hello_st* d) {
    unsigned ret = HELLO_WRITE;

    uint8_t method = SOCKS5_AUTH_NO_AUTH;

    bool found = false;
    for (uint8_t i = 0; i < d->parser.nmethods; i++) {
        if (d->parser.methods[i] == SOCKS5_AUTH_NO_AUTH) {
            found = true;
            break;
        }
    }

    if (!found) {
        method = SOCKS5_AUTH_NO_ACCEPTABLE;
        ret = ERROR;
    }

    if (-1 == hello_marshall(d->wb, method)) {
        ret = ERROR;
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
                ret = hello_process(d);
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
    unsigned  ret      = HELLO_WRITE;
    uint8_t  *ptr;
    size_t    count;
    ssize_t   n;

    ptr = buffer_read_ptr(d->wb, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if(n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(d->wb, n);
        if(!buffer_can_read(d->wb)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
                ret = REQUEST_READ;
            } else {
                ret = ERROR;
            }
        }
    }

    return ret;
}

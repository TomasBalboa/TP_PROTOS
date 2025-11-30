/**
 * hello.c - Implementación del parser de handshake SOCKS5
 */
#include "hello.h"
#include "socks5.h"
#include <string.h>

void hello_parser_init(struct hello_parser *p) {
    memset(p, 0, sizeof(*p));
    p->state = HELLO_VERSION;
}

void hello_parser_close(struct hello_parser *p) {
    // Por ahora no hay nada que liberar
    (void)p;
}

enum hello_state hello_consume(buffer *buf, struct hello_parser *p, bool *errored) {
    *errored = false;
    
    while (buffer_can_read(buf)) {
        uint8_t byte = buffer_read(buf);
        
        switch (p->state) {
            case HELLO_VERSION:
                if (byte != SOCKS5_VERSION) {
                    p->state = HELLO_ERROR;
                    *errored = true;
                    return p->state;
                }
                p->state = HELLO_NMETHODS;
                break;
                
            case HELLO_NMETHODS:
                if (byte == 0) {
                    p->state = HELLO_ERROR;
                    *errored = true;
                    return p->state;
                }
                p->nmethods = byte;
                p->methods_read = 0;
                p->state = HELLO_METHODS;
                break;
                
            case HELLO_METHODS:
                p->methods[p->methods_read++] = byte;
                if (p->methods_read == p->nmethods) {
                    p->state = HELLO_DONE;
                    return p->state;
                }
                break;
                
            case HELLO_DONE:
            case HELLO_ERROR:
                return p->state;
        }
    }
    
    return p->state;
}

bool hello_is_done(enum hello_state state, bool *errored) {
    if (errored != NULL) {
        *errored = (state == HELLO_ERROR);
    }
    return state == HELLO_DONE || state == HELLO_ERROR;
}

int hello_marshall(buffer *buf, uint8_t method) {
    size_t available;
    uint8_t *ptr = buffer_write_ptr(buf, &available);
    
    if (available < 2) {
        return -1;
    }
    
    ptr[0] = SOCKS5_VERSION;
    ptr[1] = method;
    buffer_write_adv(buf, 2);
    
    return 0;
}

// Funciones adicionales (para usar más adelante)

enum hello_state hello_parser_feed(struct hello_parser *p, uint8_t byte) {
    switch (p->state) {
        case HELLO_VERSION:
            if (byte != SOCKS5_VERSION) {
                p->state = HELLO_ERROR;
                return p->state;
            }
            p->state = HELLO_NMETHODS;
            break;
            
        case HELLO_NMETHODS:
            if (byte == 0) {
                p->state = HELLO_ERROR;
                return p->state;
            }
            p->nmethods = byte;
            p->methods_read = 0;
            p->state = HELLO_METHODS;
            break;
            
        case HELLO_METHODS:
            p->methods[p->methods_read++] = byte;
            if (p->methods_read == p->nmethods) {
                p->state = HELLO_DONE;
            }
            break;
            
        case HELLO_DONE:
        case HELLO_ERROR:
            break;
    }
    
    return p->state;
}

bool hello_has_error(enum hello_state state) {
    return state == HELLO_ERROR;
}

uint8_t hello_select_auth_method(struct hello_parser *p, 
                                  bool no_auth_enabled, 
                                  bool user_pass_enabled) {
    if (p->state != HELLO_DONE) {
        return SOCKS5_AUTH_NO_ACCEPTABLE;
    }
    
    // Buscar el método apropiado
    for (uint8_t i = 0; i < p->nmethods; i++) {
        uint8_t method = p->methods[i];
        
        if (no_auth_enabled && method == SOCKS5_AUTH_NO_AUTH) {
            return SOCKS5_AUTH_NO_AUTH;
        }
        
        if (user_pass_enabled && method == SOCKS5_AUTH_USER_PASS) {
            return SOCKS5_AUTH_USER_PASS;
        }
    }
    
    return SOCKS5_AUTH_NO_ACCEPTABLE;
}

int hello_write_response(uint8_t *buffer, uint8_t method) {
    buffer[0] = SOCKS5_VERSION;
    buffer[1] = method;
    return 2;
}

#include "hello.h"
#include "socks5.h"
#include "buffer.h"
#include <string.h>

void hello_parser_init(struct hello_parser *p) {
    memset(p, 0, sizeof(*p));
    p->state = HELLO_VERSION;
}

bool hello_parser_parse(struct hello_parser *p, buffer *buf) {
    while (buffer_can_read(buf)) {
        uint8_t byte = buffer_read(buf);
        
        switch (p->state) {
            case HELLO_VERSION:
                if (byte != SOCKS5_VERSION) {
                    p->state = HELLO_ERROR;
                    return false;
                }
                p->state = HELLO_NMETHODS;
                break;
                
            case HELLO_NMETHODS:
                if (byte == 0) {
                    p->state = HELLO_ERROR;
                    return false;
                }
                p->nmethods = byte;
                p->methods_read = 0;
                p->state = HELLO_METHODS;
                break;
                
            case HELLO_METHODS:
                p->methods[p->methods_read++] = byte;
                if (p->methods_read == p->nmethods) {
                    p->state = HELLO_DONE;
                    return true;
                }
                break;
                
            case HELLO_DONE:
            case HELLO_ERROR:
                return false;
        }
    }
    
    return p->state == HELLO_DONE;
}

uint8_t hello_select_auth_method(struct hello_parser *p, bool auth_required) {
    if (p->state != HELLO_DONE) {
        return SOCKS5_AUTH_NO_ACCEPTABLE;
    }
    
    // Buscar el método apropiado
    for (uint8_t i = 0; i < p->nmethods; i++) {
        uint8_t method = p->methods[i];
        
        if (auth_required && method == SOCKS5_AUTH_USER_PASS) {
            return SOCKS5_AUTH_USER_PASS;
        }
        
        if (!auth_required && method == SOCKS5_AUTH_NO_AUTH) {
            return SOCKS5_AUTH_NO_AUTH;
        }
    }
    
    return SOCKS5_AUTH_NO_ACCEPTABLE;
}

bool hello_write_response(buffer *buf, uint8_t method) {
    size_t available;
    uint8_t *ptr = buffer_write_ptr(buf, &available);
    
    if (available < 2) {
        return false;
    }
    
    ptr[0] = SOCKS5_VERSION;
    ptr[1] = method;
    buffer_write_adv(buf, 2);
    
    return true;
}

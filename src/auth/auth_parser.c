//RFC 1929
#include "../include/auth_parser.h"
#include <string.h>


void auth_parser_init(struct auth_parser *p) {
    memset(p, 0, sizeof(*p));
    p->state = AUTH_VERSION;
}

void auth_parser_close(struct auth_parser *p) {
    // No dynamic resources to free in current implementation
    (void)p; // suppress unused parameter warning
}  


enum auth_state auth_consume(buffer *buf, struct auth_parser *p, bool *errored) {
    *errored = false;
    
    while (buffer_can_read(buf)) {
        uint8_t byte = buffer_read(buf);
        
        switch (p->state) {
            case AUTH_VERSION:
                // RFC 1929 usa versión 0x01
                if (byte != 0x01) {
                    p->state = AUTH_ERROR;
                    *errored = true;
                    return p->state;
                }
                p->state = AUTH_USERNAME_LEN;
                break;
                
            case AUTH_USERNAME_LEN:
                if (byte == 0) {
                    p->state = AUTH_ERROR;
                    *errored = true;
                    return p->state;
                }
                p->username_len = byte;
                p->username_read = 0;
                p->state = AUTH_USERNAME;
                break;
                
            case AUTH_USERNAME:
                p->username[p->username_read++] = byte;
                if (p->username_read == p->username_len) {
                    p->username[p->username_read] = '\0';
                    p->state = AUTH_PASSWORD_LEN;
                }
                break;
                
            case AUTH_PASSWORD_LEN:
                if (byte == 0) {
                    p->state = AUTH_ERROR;
                    *errored = true;
                    return p->state;
                }
                p->password_len = byte;
                p->password_read = 0;
                p->state = AUTH_PASSWORD;
                break;
                
            case AUTH_PASSWORD:
                p->password[p->password_read++] = byte;
                if (p->password_read == p->password_len) {
                    p->password[p->password_read] = '\0';
                    p->state = AUTH_DONE;
                    return p->state;
                }
                break;
                
            case AUTH_DONE:
            case AUTH_ERROR:
                return p->state;
        }
    }
    
    return p->state;
}

bool auth_is_done(enum auth_state state) {
    return state == AUTH_DONE || state == AUTH_ERROR;
}

bool auth_has_error(enum auth_state state) {
    return state == AUTH_ERROR;
}

int auth_marshall_response(buffer *buf, bool success) {
    size_t available;
    uint8_t *ptr = buffer_write_ptr(buf, &available);
    
    if (available < 2) {
        return -1;
    }
    
    ptr[0] = 0x01;  // RFC 1929 version
    ptr[1] = success ? 0x00 : 0xFF;  // 0x00 = success, else = failure
    buffer_write_adv(buf, 2);
    
    return 0;
}

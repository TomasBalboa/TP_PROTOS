#include "request.h"
#include <string.h>
#include <arpa/inet.h>

void request_parser_init(struct request_parser *p) {
    memset(p, 0, sizeof(*p));
    p->state = REQUEST_VERSION;
}

bool request_parser_parse(struct request_parser *p, buffer *buf) {
    while (buffer_can_read(buf)) {
        uint8_t byte = buffer_read(buf);
        
        switch (p->state) {
            case REQUEST_VERSION:
                if (byte != SOCKS5_VERSION) {
                    p->state = REQUEST_ERROR;
                    return false;
                }
                p->state = REQUEST_CMD;
                break;
                
            case REQUEST_CMD:
                p->cmd = byte;
                // Solo soportamos CONNECT por ahora
                if (byte != SOCKS5_CMD_CONNECT) {
                    p->state = REQUEST_ERROR;
                    return false;
                }
                p->state = REQUEST_RSV;
                break;
                
            case REQUEST_RSV:
                // Debe ser 0x00
                if (byte != 0x00) {
                    p->state = REQUEST_ERROR;
                    return false;
                }
                p->state = REQUEST_ATYP;
                break;
                
            case REQUEST_ATYP:
                p->atyp = byte;
                p->addr_read = 0;
                
                switch (byte) {
                    case SOCKS5_ADDR_TYPE_IPV4:
                        p->state = REQUEST_ADDR_IPV4;
                        break;
                        
                    case SOCKS5_ADDR_TYPE_IPV6:
                        p->state = REQUEST_ADDR_IPV6;
                        break;
                        
                    case SOCKS5_ADDR_TYPE_DOMAIN:
                        p->state = REQUEST_ADDR_DOMAIN_LEN;
                        break;
                        
                    default:
                        p->state = REQUEST_ERROR;
                        return false;
                }
                break;
                
            case REQUEST_ADDR_DOMAIN_LEN:
                if (byte == 0 || byte > 255) {
                    p->state = REQUEST_ERROR;
                    return false;
                }
                p->dest.domain.len = byte;
                p->addr_read = 0;
                p->state = REQUEST_ADDR_DOMAIN;
                break;
                
            case REQUEST_ADDR_IPV4:
                ((uint8_t*)&p->dest.ipv4)[p->addr_read++] = byte;
                if (p->addr_read == 4) {
                    p->state = REQUEST_PORT_HIGH;
                }
                break;
                
            case REQUEST_ADDR_IPV6:
                p->dest.ipv6.s6_addr[p->addr_read++] = byte;
                if (p->addr_read == 16) {
                    p->state = REQUEST_PORT_HIGH;
                }
                break;
                
            case REQUEST_ADDR_DOMAIN:
                p->dest.domain.name[p->addr_read++] = byte;
                if (p->addr_read == p->dest.domain.len) {
                    p->dest.domain.name[p->addr_read] = '\0';
                    p->state = REQUEST_PORT_HIGH;
                }
                break;
                
            case REQUEST_PORT_HIGH:
                p->port = (uint16_t)byte << 8;
                p->state = REQUEST_PORT_LOW;
                break;
                
            case REQUEST_PORT_LOW:
                p->port |= byte;
                p->state = REQUEST_DONE;
                return true;
                
            case REQUEST_DONE:
            case REQUEST_ERROR:
                return false;
        }
    }
    
    return p->state == REQUEST_DONE;
}

void request_parser_close(struct request_parser *p) {
    // Por ahora no hay nada que liberar
    (void)p;
}

enum request_state request_consume(buffer *buf, struct request_parser *p, bool *errored) {
    *errored = false;
    
    while (buffer_can_read(buf)) {
        uint8_t byte = buffer_read(buf);
        
        switch (p->state) {
            case REQUEST_VERSION:
                if (byte != SOCKS5_VERSION) {
                    p->state = REQUEST_ERROR;
                    *errored = true;
                    return p->state;
                }
                p->state = REQUEST_CMD;
                break;
                
            case REQUEST_CMD:
                p->cmd = byte;
                // Solo soportamos CONNECT por ahora
                if (byte != SOCKS5_CMD_CONNECT) {
                    p->state = REQUEST_ERROR;
                    *errored = true;
                    return p->state;
                }
                p->state = REQUEST_RSV;
                break;
                
            case REQUEST_RSV:
                // Debe ser 0x00
                if (byte != 0x00) {
                    p->state = REQUEST_ERROR;
                    *errored = true;
                    return p->state;
                }
                p->state = REQUEST_ATYP;
                break;
                
            case REQUEST_ATYP:
                p->atyp = byte;
                p->addr_read = 0;
                
                switch (byte) {
                    case SOCKS5_ADDR_TYPE_IPV4:
                        p->state = REQUEST_ADDR_IPV4;
                        break;
                        
                    case SOCKS5_ADDR_TYPE_IPV6:
                        p->state = REQUEST_ADDR_IPV6;
                        break;
                        
                    case SOCKS5_ADDR_TYPE_DOMAIN:
                        p->state = REQUEST_ADDR_DOMAIN_LEN;
                        break;
                        
                    default:
                        p->state = REQUEST_ERROR;
                        *errored = true;
                        return p->state;
                }
                break;
                
            case REQUEST_ADDR_DOMAIN_LEN:
                if (byte == 0 || byte > 255) {
                    p->state = REQUEST_ERROR;
                    *errored = true;
                    return p->state;
                }
                p->dest.domain.len = byte;
                p->addr_read = 0;
                p->state = REQUEST_ADDR_DOMAIN;
                break;
                
            case REQUEST_ADDR_IPV4:
                ((uint8_t*)&p->dest.ipv4)[p->addr_read++] = byte;
                if (p->addr_read == 4) {
                    p->state = REQUEST_PORT_HIGH;
                }
                break;
                
            case REQUEST_ADDR_IPV6:
                p->dest.ipv6.s6_addr[p->addr_read++] = byte;
                if (p->addr_read == 16) {
                    p->state = REQUEST_PORT_HIGH;
                }
                break;
                
            case REQUEST_ADDR_DOMAIN:
                p->dest.domain.name[p->addr_read++] = byte;
                if (p->addr_read == p->dest.domain.len) {
                    p->dest.domain.name[p->addr_read] = '\0';
                    p->state = REQUEST_PORT_HIGH;
                }
                break;
                
            case REQUEST_PORT_HIGH:
                p->port = (uint16_t)byte << 8;
                p->state = REQUEST_PORT_LOW;
                break;
                
            case REQUEST_PORT_LOW:
                p->port |= byte;
                p->state = REQUEST_DONE;
                return p->state;
                
            case REQUEST_DONE:
            case REQUEST_ERROR:
                return p->state;
        }
    }
    
    return p->state;
}

bool request_is_done(enum request_state state) {
    return state == REQUEST_DONE || state == REQUEST_ERROR;
}

bool request_has_error(enum request_state state) {
    return state == REQUEST_ERROR;
}

int request_write_response(uint8_t *buffer, 
                           uint8_t reply,
                           struct in_addr *bind_addr,
                           uint16_t bind_port) {
    buffer[0] = SOCKS5_VERSION;
    buffer[1] = reply;
    buffer[2] = 0x00; // RSV
    buffer[3] = SOCKS5_ADDR_TYPE_IPV4;
    
    // Copiar dirección IPv4 (4 bytes)
    memcpy(buffer + 4, bind_addr, 4);
    
    // Puerto en network byte order
    buffer[8] = (bind_port >> 8) & 0xFF;
    buffer[9] = bind_port & 0xFF;
    
    return 10; // Total de bytes escritos
}

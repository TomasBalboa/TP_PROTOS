#ifndef REQUEST_H_
#define REQUEST_H_

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "socks5nio.h"
#include "buffer.h"

/**
 * request.h - Parser del mensaje de REQUEST de SOCKS5
 * 
 * Cliente envía:
 *   +-----+-----+-------+------+----------+----------+
 *   | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *   +-----+-----+-------+------+----------+----------+
 *   |  1  |  1  | 0x00  |  1   | Variable |    2     |
 *   +-----+-----+-------+------+----------+----------+
 */

enum request_state {
    REQUEST_VERSION,
    REQUEST_CMD,
    REQUEST_RSV,
    REQUEST_ATYP,
    REQUEST_ADDR_IPV4,
    REQUEST_ADDR_IPV6,
    REQUEST_ADDR_DOMAIN_LEN,
    REQUEST_ADDR_DOMAIN,
    REQUEST_PORT_HIGH,
    REQUEST_PORT_LOW,
    REQUEST_DONE,
    REQUEST_ERROR
};

struct request_parser {
    enum request_state state;
    
    uint8_t cmd;
    uint8_t atyp;
    
    // Para direcciones
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
        struct {
            uint8_t len;
            char    name[256];
        } domain;
    } dest;
    
    uint16_t port;
    uint8_t addr_read;  // Bytes leídos de la dirección
};

/** Inicializa el parser */
void request_parser_init(struct request_parser *p);

/**
 * Alimenta el parser con un byte.
 * Retorna el estado actual del parser.
 */
enum request_state request_parser_feed(struct request_parser *p, uint8_t byte);

/**
 * Libera recursos del parser (por ahora no hace nada)
 */
void request_parser_close(struct request_parser *p);

/**
 * Consume bytes del buffer y actualiza el parser.
 * Retorna el estado actual del parser.
 */
enum request_state request_consume(buffer *buf, struct request_parser *p, bool *errored);

/** Verifica si el parser terminó exitosamente */
bool request_is_done(enum request_state state);

/** Verifica si hubo error */
bool request_has_error(enum request_state state);

/**
 * Escribe la respuesta del request en un buffer.
 * Retorna la cantidad de bytes escritos.
 * 
 * reply: código de respuesta (enum socks5_reply)
 * bind_addr: dirección de bind (normalmente 0.0.0.0)
 * bind_port: puerto de bind (normalmente 0)
 */
int request_write_response(uint8_t *buffer, 
                           uint8_t reply,
                           struct in_addr *bind_addr,
                           uint16_t bind_port);

#endif // REQUEST_H_

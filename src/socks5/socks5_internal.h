#ifndef SOCKS5_INTERNAL_H_
#define SOCKS5_INTERNAL_H_

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>

#include "buffer.h"
#include "stm.h"
#include "hello.h"
#include "request.h"
#include "copy.h"
#include "resolver_pool.h"

/** Macro para obtener el struct client_info desde la llave de selección */
#define ATTACHMENT(key) ( (struct client_info *)(key)->data)
#define BUFFER 4096

/** Estados de la máquina de estados SOCKS5 */
enum socks_v5state {
    HELLO_READ,
    HELLO_WRITE,
    REQUEST_READ,
    REQUEST_RESOLVING,
    REQUEST_CONNECTING,
    REQUEST_WRITE,
    COPY,
    DONE,
    ERROR,
};

////////////////////////////////////////////////////////////////////
// Definición de variables para cada estado

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    /** buffer utilizado para I/O */
    buffer               *rb, *wb;
    struct hello_parser   parser;
    /** el método de autenticación seleccionado */
    uint8_t               method;
};

/** usado por REQUEST_READ, REQUEST_RESOLVING, REQUEST_CONNECTING, REQUEST_WRITE */
struct request_st {
    /** buffer utilizado para I/O */
    buffer                 *rb, *wb;
    struct request_parser   parser;
    
    /** tipo de dirección a la que nos queremos conectar */
    enum socks5_addr_type   addr_type;
    
    /** información de la conexión */
    union {
        char            fqdn[MAX_DOMAIN_LEN];
        struct sockaddr_storage storage;
    } dest_addr;
    
    /** puerto de destino */
    uint16_t                dest_port;
    
    /** respuesta al cliente */
    enum socks5_reply       reply;
};

/** usado por REQUEST_CONNECTING */
struct connecting {
    /** dirección a la que nos intentamos conectar */
    struct addrinfo *current_addr;
};

/** Estructura completa de una sesión SOCKS5 */
struct client_info {
    int                     client_fd, origin_fd;
    struct sockaddr_storage client_addr;
    struct state_machine    stm;
    union {
        struct hello_st     hello; // handshake
        struct request_st   request;
        // struct auth_st authenticate;
    } client;
    bool is_closed;
    uint8_t                 buff_origin[BUFFER], buff_client[BUFFER];
    buffer                  origin_buffer, client_buffer;
    struct addrinfo        *origin_resolution;
    struct addrinfo        *current_resolution;
    fd_selector selector;
    struct gaicb dns_req;
    char dns_host[256];
    char dns_port[6];
    char username[65];
    bool addr_resolved;
    bool is_admin;
    bool access_registered;
};

#endif

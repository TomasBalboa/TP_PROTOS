#ifndef SOCKS5_INTERNAL_H_
#define SOCKS5_INTERNAL_H_

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>

#include "buffer.h"
#include "stm.h"
#include "hello_parser.h"
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
    AUTH_READ,
    AUTH_WRITE,
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

struct auth_st {
    buffer             *rb, *wb;
    struct auth_parser   parser;
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
    /** Referencia para la próxima estructura en el pool */
    struct client_info     *next;
    
    /** File descriptors */
    int                     client_fd, origin_fd;
    
    /** Dirección del cliente */
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
    
    /** Máquina de estados */
    struct state_machine    stm;
    
    /** Estados específicos del cliente */
    union {
        struct hello_st     hello;
        struct auth_st      auth;       // AGREGAR
        struct request_st   request;
    } client;
    
    uint8_t selected_method; 
    /** Buffers para comunicación bidireccional */
    uint8_t                 buff_client[BUFFER], buff_origin[BUFFER];
    buffer                  client_buffer, origin_buffer;
    
    /** Resolución DNS */
    struct addrinfo        *origin_resolution;
    struct addrinfo        *current_resolution;
    struct resolution_job  *pending_resolution;
    
    /** Reference counting para threads */
    pthread_mutex_t         ref_mutex;
    int                     references;
    
    /** Selector */
    fd_selector             selector;
    /** Flags */
    bool                    is_closed, is_admin, access_registered;
    /** Username para autenticación */
    char                    username[65];
};

#endif

#ifndef SOCKS5_INTERNAL_H_
#define SOCKS5_INTERNAL_H_

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>

#include "buffer.h"
#include "stm.h"
#include "hello.h"
#include "request.h"
#include "copy.h"
#include "resolver_pool.h"

/** Macro para obtener el struct socks5 desde la llave de selección */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

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
struct socks5 {
    /** información del cliente */
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
    int                     client_fd;

    /** información del origen */
    int                     origin_fd;
    struct addrinfo        *origin_resolution;
    struct addrinfo        *origin_resolution_current;

    /** máquina de estados */
    struct state_machine    stm;

    /** buffers para transferir entre client y origin */
    uint8_t                 raw_buff_a[4096], raw_buff_b[4096];
    buffer                  read_buffer, write_buffer;

    /** cantidad de referencias a este objeto (protegido por mutex) */
    int                     references;
    pthread_mutex_t         ref_mutex;

    /** resolución DNS asíncrona */
    struct resolution_job  *pending_resolution;

    /** siguiente en el pool */
    struct socks5          *next;

    /** campos por cada estado */
    union {
        struct hello_st     hello;
        struct request_st   request;
        struct copy         copy;
    } client;

    union {
        struct connecting   conn;
        struct copy         copy;
    } orig;
};

#endif

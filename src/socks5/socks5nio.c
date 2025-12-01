/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "socks5nio.h"
#include "socks5_internal.h"
#include "buffer.h"
#include "stm.h"
#include "netutils.h"
#include "copy.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

// Tamaño de buffers
#define BUFFER_SIZE 4096

////////////////////////////////////////////////////////////////////
// Pool de objetos socks5

/** pool de objetos socks5 */
static struct socks5 *pool = NULL;
static unsigned       pool_size = 0;
static const unsigned max_pool  = 50;

/** Forward declaration de la tabla de estados */
static const struct state_definition client_statbl[9];

/** crea un nuevo objeto socks5 */
static struct socks5 *
socks5_new(int client_fd) {
    struct socks5 *ret;

    if (pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret       = pool;
        pool      = pool->next;
        ret->next = NULL;
        pool_size--;
    }

    if (ret == NULL) {
        return NULL;
    }

    memset(ret, 0, sizeof(*ret));

    ret->client_fd           = client_fd;
    ret->origin_fd           = -1;
    ret->origin_resolution   = NULL;
    ret->references          = 1;
    pthread_mutex_init(&ret->ref_mutex, NULL);
    ret->pending_resolution  = NULL;

    buffer_init(&ret->read_buffer,  N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);

    ret->stm.initial   = HELLO_READ;
    ret->stm.max_state = ERROR;
    ret->stm.states    = client_statbl;
    stm_init(&ret->stm);

    return ret;
}


/** realmente destruye */
static void
socks5_destroy_(struct socks5* s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    if(s->pending_resolution != NULL) {
        if(s->pending_resolution->result != NULL) {
            freeaddrinfo(s->pending_resolution->result);
        }
        free(s->pending_resolution);
        s->pending_resolution = NULL;
    }
    free(s);
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
socks5_destroy(struct socks5 *s) {
    if(s == NULL) {
        return;
    }
    
    pthread_mutex_lock(&s->ref_mutex);
    s->references--;
    int refs = s->references;
    pthread_mutex_unlock(&s->ref_mutex);
    
    if(refs == 0) {
        // Última referencia - destruir mutex y liberar
        pthread_mutex_destroy(&s->ref_mutex);
        
        if(pool_size < max_pool) {
            s->next = pool;
            pool    = s;
            pool_size++;
        } else {
            socks5_destroy_(s);
        }
    }
}

void
socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    }
}

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read   (struct selector_key *key);
static void socksv5_write  (struct selector_key *key);
static void socksv5_block  (struct selector_key *key);
static void socksv5_close  (struct selector_key *key);
static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};

/** Intenta aceptar la nueva conexión entrante*/
void
socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct socks5                *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_addr,
                                                          &client_addr_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = socks5_new(client);
    if(state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

////////////////////////////////////////////////////////////////////////////////
// HELLO
////////////////////////////////////////////////////////////////////////////////

/** inicializa las variables de los estados HELLO_… */
static void
hello_read_init(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    (void)state;

    d->rb     = &(ATTACHMENT(key)->read_buffer);
    d->wb     = &(ATTACHMENT(key)->write_buffer);
    d->method = SOCKS5_AUTH_NO_ACCEPTABLE;
    hello_parser_init(&d->parser);
}

static unsigned
hello_process(const struct hello_st* d);

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned
hello_read(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned  ret      = HELLO_READ;
        bool  error    = false;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

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

/** procesamiento del mensaje `hello' */
static unsigned
hello_process(const struct hello_st* d) {
    unsigned ret = HELLO_WRITE;

    // Seleccionamos el método (por ahora solo NO_AUTH)
    uint8_t method = SOCKS5_AUTH_NO_AUTH;
    
    // Verificamos si el cliente soporta NO_AUTH
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

/** libera recursos de hello */
static void
hello_read_close(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    (void)state;
    hello_parser_close(&d->parser);
}

/** escribe la respuesta del hello */
static unsigned
hello_write(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned  ret      = HELLO_WRITE;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

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

////////////////////////////////////////////////////////////////////////////////
// REQUEST
////////////////////////////////////////////////////////////////////////////////

/** inicializa las variables de los estados REQUEST_… */
static void
request_init(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    (void)state;

    d->rb     = &(ATTACHMENT(key)->read_buffer);
    d->wb     = &(ATTACHMENT(key)->write_buffer);
    request_parser_init(&d->parser);
}

/** libera recursos de request */
static void
request_close(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    (void)state;
    request_parser_close(&d->parser);
}

/** Incrementa referencia thread-safe */
static void
socks5_ref(struct socks5 *s) {
    if (s != NULL) {
        pthread_mutex_lock(&s->ref_mutex);
        s->references++;
        pthread_mutex_unlock(&s->ref_mutex);
    }
}

/** Escribe respuesta de error al cliente */
static unsigned
request_write_error_response(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *d = &s->client.request;
    
    // Preparar respuesta de error
    struct in_addr bind_addr;
    bind_addr.s_addr = INADDR_ANY;
    
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(d->wb, &nbytes);
    
    int written = request_write_response(ptr, d->reply, &bind_addr, 0);
    buffer_write_adv(d->wb, written);
    
    // Escribir al cliente
    if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
        return REQUEST_WRITE;
    }
    
    return ERROR;
}

/** Intenta conectar al origin (después de resolver) */
static unsigned
request_try_connect(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *d = &s->client.request;
    
    // Intentar cada dirección resuelta
    while (s->origin_resolution_current != NULL) {
        int origin_fd = socket(s->origin_resolution_current->ai_family,
                               s->origin_resolution_current->ai_socktype,
                               s->origin_resolution_current->ai_protocol);
        
        if (origin_fd < 0) {
            s->origin_resolution_current = s->origin_resolution_current->ai_next;
            continue;
        }
        
        // Modo no bloqueante
        if (selector_fd_set_nio(origin_fd) == -1) {
            close(origin_fd);
            s->origin_resolution_current = s->origin_resolution_current->ai_next;
            continue;
        }
        
        // Conectar (no bloqueante)
        int conn_ret = connect(origin_fd, 
                              s->origin_resolution_current->ai_addr,
                              s->origin_resolution_current->ai_addrlen);
        
        if (conn_ret == 0 || (conn_ret == -1 && errno == EINPROGRESS)) {
            // Conexión en progreso
            s->origin_fd = origin_fd;
            d->reply = SOCKS5_REPLY_SUCCESS;
            
            // Preparar respuesta
            struct in_addr bind_addr;
            bind_addr.s_addr = INADDR_ANY;
            
            size_t nbytes;
            uint8_t *ptr = buffer_write_ptr(d->wb, &nbytes);
            int written = request_write_response(ptr, d->reply, &bind_addr, 0);
            buffer_write_adv(d->wb, written);
            
            // Registrar origin_fd
            selector_status ss = selector_register(key->s, s->origin_fd,
                                                  &socks5_handler,
                                                  OP_WRITE, s);
            if (ss != SELECTOR_SUCCESS) {
                close(origin_fd);
                s->origin_fd = -1;
                return ERROR;
            }
            
            // Escribir respuesta al cliente
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                return REQUEST_WRITE;
            }
            return ERROR;
        }
        
        close(origin_fd);
        s->origin_resolution_current = s->origin_resolution_current->ai_next;
    }
    
    // Todas las conexiones fallaron
    d->reply = SOCKS5_REPLY_HOST_UNREACHABLE;
    return request_write_error_response(key);
}

/** Inicia resolución asíncrona */
static unsigned
request_resolving_init_do(const unsigned state, struct selector_key *key) {
    (void)state;
    struct socks5 *s = ATTACHMENT(key);
    struct request_parser *p = &s->client.request.parser;
    
    // Crear job de resolución
    struct resolution_job *job = malloc(sizeof(*job));
    if (job == NULL) {
        return ERROR;
    }
    
    memset(job, 0, sizeof(*job));
    
    // Preparar datos de entrada
    if (p->atyp == SOCKS5_ADDR_TYPE_IPV4) {
        inet_ntop(AF_INET, &p->dest.ipv4, job->hostname, sizeof(job->hostname));
    } else if (p->atyp == SOCKS5_ADDR_TYPE_DOMAIN) {
        strncpy(job->hostname, p->dest.domain.name, sizeof(job->hostname) - 1);
        job->hostname[sizeof(job->hostname) - 1] = '\0';
    } else {
        free(job);
        s->client.request.reply = SOCKS5_REPLY_ADDR_TYPE_NOT_SUPPORTED;
        return request_write_error_response(key);
    }
    
    snprintf(job->port, sizeof(job->port), "%d", p->port);
    
    fprintf(stderr, "DEBUG: About to resolve hostname='%s' port='%s'\n", 
            job->hostname, job->port);
    
    memset(&job->hints, 0, sizeof(job->hints));
    job->hints.ai_family = AF_UNSPEC;
    job->hints.ai_socktype = SOCK_STREAM;
    job->hints.ai_flags = AI_ADDRCONFIG;
    
    // Configurar notificación
    job->selector = key->s;
    job->client_fd = s->client_fd;
    job->completed = 0;
    pthread_mutex_init(&job->mutex, NULL);
    
    // Incrementar referencia (el thread worker mantiene una referencia)
    socks5_ref(s);
    job->socks5_ref = s;
    
    s->pending_resolution = job;
    
    // Enviar a thread pool
    if (resolver_pool_submit(job) != 0) {
        // Error al encolar
        s->pending_resolution = NULL;
        free(job);
        socks5_destroy(s);  // Liberar referencia
        return ERROR;
    }
    
    // Desactivar intereses en client_fd mientras esperamos
    selector_set_interest_key(key, OP_NOOP);
    
    return REQUEST_RESOLVING;
}

/** Wrapper para on_arrival */
static void
request_resolving_init(const unsigned state, struct selector_key *key) {
    fprintf(stderr, "DEBUG: request_resolving_init called\n");
    request_resolving_init_do(state, key);
}

/** Handler cuando la resolución se completa (llamado por selector) */
static unsigned
request_resolving_block_ready(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct resolution_job *job = s->pending_resolution;
    
    if (job == NULL) {
        return ERROR;
    }
    
    // Verificar que realmente completó (race condition protection)
    pthread_mutex_lock(&job->mutex);
    int is_completed = job->completed;
    pthread_mutex_unlock(&job->mutex);
    
    if (is_completed == 0) {
        // Aún no terminó, volver a esperar
        return REQUEST_RESOLVING;
    }
    
    unsigned ret;
    
    if (job->error_code != 0 || job->result == NULL) {
        // Error en resolución
        fprintf(stderr, "DEBUG: DNS resolution failed - error_code=%d, result=%p\n", 
                job->error_code, (void*)job->result);
        s->client.request.reply = SOCKS5_REPLY_HOST_UNREACHABLE;
        ret = request_write_error_response(key);
    } else {
        // Resolución exitosa
        s->origin_resolution = job->result;
        s->origin_resolution_current = job->result;
        job->result = NULL;  // Transferir ownership
        
        // Intentar conectar
        ret = request_try_connect(key);
    }
    
    // Limpiar job
    if (job->result != NULL) {
        freeaddrinfo(job->result);
    }
    pthread_mutex_destroy(&job->mutex);
    free(job);
    s->pending_resolution = NULL;
    
    // Liberar referencia del worker
    socks5_destroy(job->socks5_ref);
    
    return ret;
}

/** Lee el request del cliente */
static unsigned
request_read(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    unsigned  ret      = REQUEST_READ;
    bool      error    = false;
    uint8_t  *ptr;
    size_t    count;
    ssize_t   n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    
    if(n > 0) {
        buffer_write_adv(d->rb, n);
        const enum request_state st = request_consume(d->rb, &d->parser, &error);
        
        if(st == REQUEST_ERROR) {
            // Parser detectó request inválido
            d->reply = SOCKS5_REPLY_GENERAL_FAILURE;
            
            struct in_addr bind_addr;
            bind_addr.s_addr = INADDR_ANY;
            
            size_t nbytes;
            uint8_t *wptr = buffer_write_ptr(d->wb, &nbytes);
            int written = request_write_response(wptr, d->reply, &bind_addr, 0);
            buffer_write_adv(d->wb, written);
            
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = REQUEST_WRITE;
            } else {
                ret = ERROR;
            }
        } else if(request_is_done(st)) {
            // Request completo y válido - iniciar resolución asíncrona
            ret = REQUEST_RESOLVING;
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

/** Escribe la respuesta del request al cliente */
static unsigned
request_write(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    struct socks5 *s = ATTACHMENT(key);
    unsigned  ret      = REQUEST_WRITE;
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
            // Terminamos de enviar la respuesta al cliente
            if(s->origin_fd < 0) {
                ret = ERROR;
            } else {
                // La respuesta está enviada. El origin_fd ya está registrado con OP_WRITE
                // esperando que la conexión se complete. 
                // Desactivar interés en client_fd hasta que origin esté listo.
                selector_set_interest_key(key, OP_NOOP);
                ret = REQUEST_CONNECTING;
            }
        }
    }

    return ret;
}

/** Handler cuando el origin_fd se vuelve writable (conexión completada) */
static unsigned
request_connecting_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    
    // Verificar que la conexión se completó sin errores
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
        if (error != 0) {
            return ERROR;
        }
    }
    
    // Conexión exitosa - pasar a COPY
    buffer_reset(&s->read_buffer);
    buffer_reset(&s->write_buffer);
    
    return COPY;
}

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state            = HELLO_READ,
        .on_arrival       = hello_read_init,
        .on_departure     = hello_read_close,
        .on_read_ready    = hello_read,
    },
    {
        .state            = HELLO_WRITE,
        .on_write_ready   = hello_write,
    },
    {
        .state            = REQUEST_READ,
        .on_arrival       = request_init,
        .on_departure     = request_close,
        .on_read_ready    = request_read,
    },
    {
        .state            = REQUEST_RESOLVING,
        .on_arrival       = request_resolving_init,
        .on_block_ready   = request_resolving_block_ready,
    },
    {
        .state            = REQUEST_CONNECTING,
        .on_write_ready   = request_connecting_write,
    },
    {
        .state            = REQUEST_WRITE,
        .on_write_ready   = request_write,
    },
    {
        .state            = COPY,
        .on_arrival       = copy_init,
        .on_read_ready    = copy_read,
        .on_write_ready   = copy_write,
    },
    {
        .state            = DONE,
    },
    {
        .state            = ERROR,
    }
};

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.
static void
socksv5_done(struct selector_key* key);

static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void
socksv5_done(struct selector_key* key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for(unsigned i = 0; i < N(fds); i++) {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}

/* request_handler.c
 * Módulo que contiene la lógica del estado REQUEST extraída de socks5nio.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#include "socks5_internal.h"
#include "request.h"
#include "resolver_pool.h"
#include "request_handler.h"
#include "buffer.h"
#include "copy.h"

/* inicializa las variables de los estados REQUEST_… */
void request_init(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    (void)state;

    d->rb     = &(ATTACHMENT(key)->client_buffer);
    d->wb     = &(ATTACHMENT(key)->origin_buffer);
    request_parser_init(&d->parser);
}

/* libera recursos de request */
void request_close(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    (void)state;
    request_parser_close(&d->parser);
}

/* Incrementa referencia thread-safe */
static void socks5_ref_local(struct client_info *s) {
    if (s != NULL) {
        pthread_mutex_lock(&s->ref_mutex);
        s->references++;
        pthread_mutex_unlock(&s->ref_mutex);
    }
}

/* Escribe respuesta de error al cliente */
unsigned request_write_error_response(struct selector_key *key) {
    struct client_info *s = ATTACHMENT(key);
    struct request_st *d = &s->client.request;
    
    /* Preparar respuesta de error */
    struct in_addr bind_addr;
    bind_addr.s_addr = INADDR_ANY;
    
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(d->wb, &nbytes);
    
    int written = request_write_response(ptr, d->reply, &bind_addr, 0);
    buffer_write_adv(d->wb, written);
    
    /* Escribir al cliente */
    if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
        return REQUEST_WRITE;
    }
    
    return ERROR;
}

/* Intenta conectar al origin (después de resolver) */
unsigned request_try_connect(struct selector_key *key) {
    struct client_info *s = ATTACHMENT(key);
    struct request_st *d = &s->client.request;
    
    /* Intentar cada dirección resuelta */
    while (s->current_resolution != NULL) {
        int origin_fd = socket(s->current_resolution->ai_family,
                               s->current_resolution->ai_socktype,
                               s->current_resolution->ai_protocol);
        
        if (origin_fd < 0) {
            s->current_resolution = s->current_resolution->ai_next;
            continue;
        }
        
        /* Modo no bloqueante */
        if (selector_fd_set_nio(origin_fd) == -1) {
            close(origin_fd);
            s->current_resolution = s->current_resolution->ai_next;
            continue;
        }
        
        /* Conectar (no bloqueante) */
        int conn_ret = connect(origin_fd, 
                              s->current_resolution->ai_addr,
                              s->current_resolution->ai_addrlen);
        
        if (conn_ret == 0 || (conn_ret == -1 && errno == EINPROGRESS)) {
            /* Conexión en progreso */
            s->origin_fd = origin_fd;
            d->reply = SOCKS5_REPLY_SUCCESS;
            
            /* Preparar respuesta */
            struct in_addr bind_addr;
            bind_addr.s_addr = INADDR_ANY;
            
            size_t nbytes;
            uint8_t *ptr = buffer_write_ptr(d->wb, &nbytes);
            int written = request_write_response(ptr, d->reply, &bind_addr, 0);
            buffer_write_adv(d->wb, written);
            
            /* Registrar origin_fd */
            selector_status ss = selector_register(key->s, s->origin_fd,
                                                  &socks5_handler,
                                                  OP_WRITE, s);
            if (ss != SELECTOR_SUCCESS) {
                close(origin_fd);
                s->origin_fd = -1;
                return ERROR;
            }
            
            /* Escribir respuesta al cliente */
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                return REQUEST_WRITE;
            }
            return ERROR;
        }
        
        close(origin_fd);
        s->current_resolution = s->current_resolution->ai_next;
    }
    
    /* Todas las conexiones fallaron */
    d->reply = SOCKS5_REPLY_HOST_UNREACHABLE;
    return request_write_error_response(key);
}

/* Inicia resolución asíncrona */
unsigned request_resolving_init_do(const unsigned state, struct selector_key *key) {
    (void)state;
    struct client_info *s = ATTACHMENT(key);
    struct request_parser *p = &s->client.request.parser;
    
    /* Crear job de resolución */
    struct resolution_job *job = malloc(sizeof(*job));
    if (job == NULL) {
        return ERROR;
    }
    
    memset(job, 0, sizeof(*job));
    
    /* Preparar datos de entrada */
    if (p->atyp == SOCKS5_ADDR_TYPE_IPV4) {
        inet_ntop(AF_INET, &p->dest.ipv4, job->hostname, sizeof(job->hostname));
    } else if (p->atyp == SOCKS5_ADDR_TYPE_IPV6) {
        inet_ntop(AF_INET6, &p->dest.ipv6, job->hostname, sizeof(job->hostname));
    } else if (p->atyp == SOCKS5_ADDR_TYPE_DOMAIN) {
        strncpy(job->hostname, p->dest.domain.name, sizeof(job->hostname) - 1);
        job->hostname[sizeof(job->hostname) - 1] = '\0';
    } else {
        free(job);
        s->client.request.reply = SOCKS5_REPLY_ADDR_TYPE_NOT_SUPPORTED;
        return request_write_error_response(key);
    }
    
    snprintf(job->port, sizeof(job->port), "%d", p->port);
    
    memset(&job->hints, 0, sizeof(job->hints));
    job->hints.ai_family = AF_UNSPEC;
    job->hints.ai_socktype = SOCK_STREAM;
    job->hints.ai_flags = AI_ADDRCONFIG;
    
    /* Configurar notificación */
    job->selector = key->s;
    job->client_fd = s->client_fd;
    job->completed = 0;
    pthread_mutex_init(&job->mutex, NULL);
    
    /* Incrementar referencia (el thread worker mantiene una referencia) */
    socks5_ref_local(s);
    job->socks5_ref = s;
    
    s->pending_resolution = job;
    
    /* Enviar a thread pool */
    if (resolver_pool_submit(job) != 0) {
        /* Error al encolar */
        s->pending_resolution = NULL;
        free(job);
        socks5_destroy(s);  /* Liberar referencia */
        return ERROR;
    }
    
    /* Desactivar intereses en client_fd mientras esperamos */
    selector_set_interest_key(key, OP_NOOP);
    
    return REQUEST_RESOLVING;
}

/* Wrapper para on_arrival */
void request_resolving_init(const unsigned state, struct selector_key *key) {
    request_resolving_init_do(state, key);
}

/* Handler cuando la resolución se completa (llamado por selector) */
unsigned request_resolving_block_ready(struct selector_key *key) {
    struct client_info *s = ATTACHMENT(key);
    struct resolution_job *job = s->pending_resolution;
    
    if (job == NULL) {
        return ERROR;
    }
    
    /* Verificar que realmente completó (race condition protection) */
    pthread_mutex_lock(&job->mutex);
    int is_completed = job->completed;
    pthread_mutex_unlock(&job->mutex);
    
    if (is_completed == 0) {
        /* Aún no terminó, volver a esperar */
        return REQUEST_RESOLVING;
    }
    
    unsigned ret;
    
    if (job->error_code != 0 || job->result == NULL) {
        /* Error en resolución */
        s->client.request.reply = SOCKS5_REPLY_HOST_UNREACHABLE;
        ret = request_write_error_response(key);
    } else {
        /* Resolución exitosa */
        s->origin_resolution = job->result;
        s->current_resolution = job->result;
        job->result = NULL;  /* Transferir ownership */
        
        /* Intentar conectar */
        ret = request_try_connect(key);
    }
    
    /* Limpiar job */
    if (job->result != NULL) {
        freeaddrinfo(job->result);
    }
    pthread_mutex_destroy(&job->mutex);
    free(job);
    s->pending_resolution = NULL;
    
    return ret;
}

/* Lee el request del cliente */
unsigned request_read(struct selector_key *key) {
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
            /* Parser detectó request inválido */
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
            /* Request completo y válido - iniciar resolución asíncrona */
            ret = REQUEST_RESOLVING;
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

/* Escribe la respuesta del request al cliente */
unsigned request_write(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    struct client_info *s = ATTACHMENT(key);
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
            /* Terminamos de enviar la respuesta al cliente */
            if(s->origin_fd < 0) {
                ret = ERROR;
            } else {
                /* La respuesta está enviada. El origin_fd ya está registrado con OP_WRITE
                 * esperando que la conexión se complete. 
                 * Desactivar interés en client_fd hasta que origin esté listo.
                 */
                selector_set_interest_key(key, OP_NOOP);
                ret = REQUEST_CONNECTING;
            }
        }
    }

    return ret;
}

/* Handler cuando el origin_fd se vuelve writable (conexión completada) */
unsigned request_connecting_write(struct selector_key *key) {
    struct client_info *s = ATTACHMENT(key);
    
    /* Verificar que la conexión se completó sin errores */
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
        if (error != 0) {
            return ERROR;
        }
    }
    
    buffer_reset(&s->client_buffer);
    buffer_reset(&s->origin_buffer);
    
    return COPY;
}

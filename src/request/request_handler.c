/* request_handler.c
 * Módulo que contiene la lógica del estado REQUEST extraída de socks5nio.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include "logging.h"
#include "socks5_internal.h"
#include "request.h"
#include "resolver_pool.h"
#include "request_handler.h"
#include "buffer.h"
#include "copy.h"
#include "users.h"

/* Constantes para getnameinfo() si no están definidas por el sistema */
#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

#ifndef NI_MAXSERV
#define NI_MAXSERV 32
#endif

/* inicializa las variables de los estados REQUEST_… */
void request_init(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    (void)state;

    logf(LOG_DEBUG, "[REQUEST] request_init fd=%d", key->fd);
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

    logf(LOG_INFO, "[REQUEST] request_try_connect fd=%d", key->fd);

    /* Intentar cada dirección resuelta */
    while (s->current_resolution != NULL) {
        logf(LOG_DEBUG, "[REQUEST] Trying connection attempt fd=%d", key->fd);

        int origin_fd = socket(s->current_resolution->ai_family,
                               s->current_resolution->ai_socktype,
                               s->current_resolution->ai_protocol);

        if (origin_fd < 0) {
            logf(LOG_WARNING, "[REQUEST] socket() failed: %s fd=%d", strerror(errno), key->fd);
            s->current_resolution = s->current_resolution->ai_next;
            continue;
        }
        
        /* Verifico que el FD esté dentro del límite de select() */
        if (origin_fd >= FD_SETSIZE) {
            logf(LOG_WARNING, "[REQUEST] origin_fd=%d excede FD_SETSIZE (%d), rechazando conexión", origin_fd, FD_SETSIZE);
            close(origin_fd);
            s->current_resolution = s->current_resolution->ai_next;
            continue;
        }

        logf(LOG_DEBUG, "[REQUEST] Created origin_fd=%d for client_fd=%d", origin_fd, key->fd);

        /* Modo no bloqueante */
        if (selector_fd_set_nio(origin_fd) == -1) {
            logf(LOG_WARNING, "[REQUEST] selector_fd_set_nio failed fd=%d origin_fd=%d", key->fd, origin_fd);
            close(origin_fd);
            s->current_resolution = s->current_resolution->ai_next;
            continue;
        }

        /* Conectar (no bloqueante) */
        int conn_ret = connect(origin_fd,
                               s->current_resolution->ai_addr,
                               s->current_resolution->ai_addrlen);

        logf(LOG_DEBUG, "[REQUEST] connect() returned %d errno=%d (%s) fd=%d origin_fd=%d",
             conn_ret, errno, strerror(errno), key->fd, origin_fd);

        if (conn_ret == 0 || (conn_ret == -1 && errno == EINPROGRESS)) {
            /* Registro de conexión en historial de usuario (si tenemos username) */
            if (s->username[0] != '\0') {
                char hostbuf[NI_MAXHOST];
                char portbuf[NI_MAXSERV];

                if (getnameinfo(s->current_resolution->ai_addr,
                                s->current_resolution->ai_addrlen,
                                hostbuf, sizeof(hostbuf),
                                portbuf, sizeof(portbuf),
                                NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                    char dest[NI_MAXHOST + NI_MAXSERV + 2];  /* +2 para ':' y '\0' */
                    snprintf(dest, sizeof(dest), "%s:%s", hostbuf, portbuf);
                    users_add_access_log(s->username, dest);
                }
            }

            /* Conexión en progreso */
            s->origin_fd = origin_fd;
            d->reply = SOCKS5_REPLY_SUCCESS;
            
            logf(LOG_INFO, "[REQUEST] Connection initiated, origin_fd=%d client_fd=%d", origin_fd, key->fd);
            
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
                logf(LOG_ERROR, "[REQUEST] selector_register failed for origin_fd=%d: %d", origin_fd, ss);
                close(origin_fd);
                s->origin_fd = -1;
                return ERROR;
            }
            
            logf(LOG_INFO, "[REQUEST] origin_fd=%d registered with selector", origin_fd);
            
            /* Escribir respuesta al cliente */
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                logf(LOG_INFO, "[REQUEST] Transitioning to REQUEST_WRITE fd=%d", key->fd);
                return REQUEST_WRITE;
            }
            logf(LOG_ERROR, "[REQUEST] selector_set_interest_key failed fd=%d", key->fd);
            return ERROR;
        }

        logf(LOG_WARNING, "[REQUEST] connect failed, trying next address fd=%d", key->fd);
        close(origin_fd);
        s->current_resolution = s->current_resolution->ai_next;
    }

    /* Todas las conexiones fallaron */
    logf(LOG_ERROR, "[REQUEST] All connection attempts failed fd=%d", key->fd);
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
        logf(LOG_INFO, "[REQUEST] IPv4 address to resolve: %s", job->hostname);
    } else if (p->atyp == SOCKS5_ADDR_TYPE_IPV6) {
        inet_ntop(AF_INET6, &p->dest.ipv6, job->hostname, sizeof(job->hostname));
        logf(LOG_INFO, "[REQUEST] IPv6 address to resolve: %s", job->hostname);
    } else if (p->atyp == SOCKS5_ADDR_TYPE_DOMAIN) {
        strncpy(job->hostname, p->dest.domain.name, sizeof(job->hostname) - 1);
        job->hostname[sizeof(job->hostname) - 1] = '\0';
        logf(LOG_INFO, "[REQUEST] Domain to resolve: %s", job->hostname);
    } else {
        free(job);
        s->client.request.reply = SOCKS5_REPLY_ADDR_TYPE_NOT_SUPPORTED;
        return request_write_error_response(key);
    }
    
    snprintf(job->port, sizeof(job->port), "%d", p->port);
    logf(LOG_INFO, "[REQUEST] Submitting resolution job: %s:%s fd=%d", job->hostname, job->port, key->fd);
    
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
        logf(LOG_ERROR, "[REQUEST] Failed to submit resolution job fd=%d", key->fd);
        s->pending_resolution = NULL;
        free(job);
        socks5_destroy(s);  /* Liberar referencia */
        return ERROR;
    }
    
    logf(LOG_INFO, "[REQUEST] Resolution job submitted successfully fd=%d", key->fd);
    
    /* Desactivar intereses en client_fd mientras esperamos */
    selector_set_interest_key(key, OP_NOOP);
    
    return REQUEST_RESOLVING;
}

/* Wrapper para on_arrival */
void request_resolving_init(const unsigned state, struct selector_key *key) {
    logf(LOG_INFO, "[REQUEST] request_resolving_init called fd=%d", key->fd);
    request_resolving_init_do(state, key);
}

/* Handler cuando la resolución se completa (llamado por selector) */
unsigned request_resolving_block_ready(struct selector_key *key) {
    struct client_info *s = ATTACHMENT(key);
    struct resolution_job *job = s->pending_resolution;
    
    logf(LOG_INFO, "[REQUEST] request_resolving_block_ready called fd=%d", key->fd);
    
    if (job == NULL) {
        logf(LOG_ERROR, "[REQUEST] No pending resolution job fd=%d", key->fd);
        return ERROR;
    }
    
    /* Verificar que realmente completó (race condition protection) */
    pthread_mutex_lock(&job->mutex);
    int is_completed = job->completed;
    pthread_mutex_unlock(&job->mutex);
    
    logf(LOG_INFO, "[REQUEST] job completed=%d fd=%d", is_completed, key->fd);
    
    if (is_completed == 0) {
        /* Aún no terminó, volver a esperar */
        logf(LOG_DEBUG, "[REQUEST] Job not completed yet, staying in REQUEST_RESOLVING fd=%d", key->fd);
        return REQUEST_RESOLVING;
    }
    
    unsigned ret;
    
    if (job->error_code != 0 || job->result == NULL) {
        /* Error en resolución */
        logf(LOG_WARNING, "[REQUEST] Resolution failed: error_code=%d result=%p fd=%d", 
             job->error_code, (void*)job->result, key->fd);
        s->client.request.reply = SOCKS5_REPLY_HOST_UNREACHABLE;
        ret = request_write_error_response(key);
    } else {
        /* Resolución exitosa */
        logf(LOG_INFO, "[REQUEST] Resolution successful, connecting fd=%d", key->fd);
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

    logf(LOG_DEBUG, "[REQUEST] request_read fd=%d", key->fd);
    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    
    logf(LOG_DEBUG, "[REQUEST] request_read fd=%d recv=%zd bytes", key->fd, n);
    
    if(n > 0) {
        buffer_write_adv(d->rb, n);
        const enum request_state st = request_consume(d->rb, &d->parser, &error);
        
        logf(LOG_DEBUG, "[REQUEST] parser state=%d error=%d fd=%d", st, error, key->fd);
        
        if(st == REQUEST_ERROR_CMD_NOT_SUPPORTED) {
            d->reply = SOCKS5_REPLY_CMD_NOT_SUPPORTED;
        } else if(st == REQUEST_ERROR) {
            d->reply = SOCKS5_REPLY_GENERAL_FAILURE;
        }
        
        if(st == REQUEST_ERROR_CMD_NOT_SUPPORTED || st == REQUEST_ERROR) {
            struct in_addr bind_addr = {.s_addr = INADDR_ANY};
            size_t nbytes;
            uint8_t *wptr = buffer_write_ptr(d->wb, &nbytes);
            buffer_write_adv(d->wb, request_write_response(wptr, d->reply, &bind_addr, 0));
            
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = REQUEST_WRITE;
            } else {
                ret = ERROR;
            }
        } else if(request_is_done(st)) {
            /* Request completo y válido - iniciar resolución asíncrona */
            logf(LOG_INFO, "[REQUEST] request done, transitioning to REQUEST_RESOLVING fd=%d atyp=%d", key->fd, d->parser.atyp);
            ret = REQUEST_RESOLVING;
        }
    } else {
        ret = ERROR;
    }

    logf(LOG_DEBUG, "[REQUEST] request_read returning state=%d fd=%d", ret, key->fd);
    return ret;
}

/* Escribe la respuesta del request al cliente */
unsigned request_write(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    struct client_info *s = ATTACHMENT(key);
    unsigned  ret      = REQUEST_WRITE;
    uint8_t  *ptr;
    size_t    count;
    ssize_t   n;

    /* Si este evento es del origin_fd, ignorarlo - estamos esperando escribir al cliente */
    if (key->fd == s->origin_fd) {
        return REQUEST_WRITE;
    }

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

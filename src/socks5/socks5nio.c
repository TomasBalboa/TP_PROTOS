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
#include "hello.h"
#include "request_handler.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

// Tamaño de buffers
#define BUFFER_SIZE 4096

////////////////////////////////////////////////////////////////////
// Pool de objetos socks5

/** pool de objetos socks5 */
static struct client_info *pool = NULL;
static unsigned       pool_size = 0;
static const unsigned max_pool  = 50;

/** Forward declaration de la tabla de estados */
static const struct state_definition client_statbl[9];

/** crea un nuevo objeto socks5 */
static struct client_info *
socks5_new(int client_fd) {
    struct client_info *ret;

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

    ret->client_fd                = client_fd;
    ret->origin_fd                = -1;
    ret->origin_resolution        = NULL;
    ret->current_resolution       = NULL;
    ret->references               = 1;
    pthread_mutex_init(&ret->ref_mutex, NULL);
    ret->pending_resolution       = NULL;

    buffer_init(&ret->client_buffer, N(ret->buff_client), ret->buff_client);
    buffer_init(&ret->origin_buffer, N(ret->buff_origin), ret->buff_origin);

    ret->stm.initial   = HELLO_READ;
    ret->stm.max_state = ERROR;
    ret->stm.states    = client_statbl;
    stm_init(&ret->stm);

    return ret;
}


/** realmente destruye */
static void
socks5_destroy_(struct client_info* s) {
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
 * destruye un  `struct client_info', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
socks5_destroy(struct client_info *s) {
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
    struct client_info *next, *s;
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
    struct client_info                *state           = NULL;

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
// REQUEST
////////////////////////////////////////////////////////////////////////////////

/* La lógica relacionada con REQUEST fue movida a `request_handler.c`.
 * Las funciones están declaradas en `src/include/request_handler.h`.
 */

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
static void socksv5_done(struct selector_key* key);

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

void
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
    
    // Liberar la estructura (decrementa referencias)
    socks5_destroy(ATTACHMENT(key));
}

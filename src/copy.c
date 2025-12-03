/**
 * copy.c - Implementación del túnel bidireccional de datos (estado COPY)
 */
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include "./include/copy.h"
#include "./include/socks5_internal.h"
#include "./include/socks5nio.h"

// static fd_interest copy_compute_interests(fd_selector s, struct copy *d);
static unsigned read_aux(struct selector_key *key, int fd, buffer *buffer);
static unsigned write_aux(struct selector_key *key, buffer *buffer);

/**
 * Computa los intereses del selector para un fd basado en el estado de los buffers
 */
// static fd_interest copy_compute_interests(fd_selector s, struct copy *d) {
//     fd_interest ret = OP_NOOP;
    
//     if (d->rb != NULL && buffer_can_write(d->rb)) {
//         ret |= OP_READ;
//     }
//     if (d->wb != NULL && buffer_can_read(d->wb)) {
//         ret |= OP_WRITE;
//     }
    
//     if (ret != d->duplex) {
//         if (SELECTOR_SUCCESS == selector_set_interest(s, *d->fd, ret)) {
//             d->duplex = ret;
//         }
//     }
    
//     return ret;
// }

// /**
//  * Determina si la copia terminó (ambos lados cerraron y buffers vacíos)
//  */
// static bool copy_is_done(struct client_info *s) {
//     // Si algún fd es inválido, terminamos
//     if (s->client_fd == -1 || s->origin_fd == -1) {
//         return true;
//     }
    
//     // Terminamos cuando ambos lados cerraron (OP_NOOP) y no hay datos pendientes
//     bool client_closed = (s->client.copy.duplex == OP_NOOP);
//     bool origin_closed = (s->orig.copy.duplex == OP_NOOP);
//     bool no_client_data = !buffer_can_read(&s->read_buffer);
//     bool no_origin_data = !buffer_can_read(&s->write_buffer);
    
//     return client_closed && origin_closed && no_client_data && no_origin_data;
// }

void copy_init(const unsigned state, struct selector_key *key) {
    (void) state;
    struct client_info *s = ATTACHMENT(key);
    
    if(selector_set_interest(key->s, s->client_fd, OP_READ) != SELECTOR_SUCCESS || selector_set_interest(key->s, s->origin_fd, OP_READ) != SELECTOR_SUCCESS)
        socksv5_close(key);
}

unsigned copy_read(struct selector_key *key) {
    struct client_info *s = ATTACHMENT(key);

    if (key->fd == s->client_fd) {
        return read_aux(key,s->origin_fd,&s->origin_buffer);
    } else if (key->fd == s->origin_fd) {
        return read_aux(key,s->client_fd,&s->client_buffer);
    }
    return ERROR;
}

unsigned copy_write(struct selector_key *key) {
    struct client_info *s = ATTACHMENT(key);

    if (key->fd == s->client_fd) {
        return write_aux(key,&s->client_buffer);
    } else if (key->fd == s->origin_fd) {
        return write_aux(key,&s->origin_buffer);
    }
    return ERROR;
}

static unsigned read_aux(struct selector_key *key, int fd, buffer *buffer){
    if(!buffer_can_write(buffer)){
        return COPY;
    }

    size_t available_space;
    uint8_t *read = buffer_write_ptr(buffer, &available_space);
    ssize_t bytes_read = recv(key->fd, read, available_space, 0);

    if(bytes_read < 0) {
        // perror("reading failed");
        return ERROR;
    }else if(bytes_read == 0){
        return DONE;
    }
    buffer_write_adv(buffer, bytes_read);
    
    uint8_t *write = buffer_read_ptr(buffer, &available_space);
    ssize_t bytes_written = send(fd, write, available_space, MSG_NOSIGNAL);

    if(bytes_written > 0){
        buffer_read_adv(buffer, bytes_written);
        // metrica
    }

    if(buffer_can_read(buffer) || (bytes_written < 0 && errno == EWOULDBLOCK)){
        if(selector_set_interest(key->s, fd, OP_WRITE) != SELECTOR_SUCCESS){
            return ERROR;
        }
    }
    return COPY;
}

static unsigned write_aux(struct selector_key *key, buffer *buffer){
    if(!buffer_can_read(buffer)){
        return COPY;
    }

    size_t available_space;
    uint8_t *write = buffer_read_ptr(buffer, &available_space);
    ssize_t bytes_written = send(key->fd, write, available_space, MSG_NOSIGNAL);

    if(bytes_written <= 0){
        // perror("send failed");
        return ERROR;
    }

    // metrica

    buffer_read_adv(buffer, bytes_written);

    if(!buffer_can_read(buffer)){
        if(selector_set_interest(key->s, key->fd, OP_READ) != SELECTOR_SUCCESS){
            return ERROR;
        }
    }

    return COPY;
}

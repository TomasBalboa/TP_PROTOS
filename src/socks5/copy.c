/**
 * copy.c - Implementación del túnel bidireccional de datos (estado COPY)
 */
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include "copy.h"
#include "socks5_internal.h"

/**
 * Computa los intereses del selector para un fd basado en el estado de los buffers
 */
static fd_interest
copy_compute_interests(fd_selector s, struct copy *d) {
    fd_interest ret = OP_NOOP;
    
    if (d->rb != NULL && buffer_can_write(d->rb)) {
        ret |= OP_READ;
    }
    if (d->wb != NULL && buffer_can_read(d->wb)) {
        ret |= OP_WRITE;
    }
    
    if (ret != d->duplex) {
        if (SELECTOR_SUCCESS == selector_set_interest(s, *d->fd, ret)) {
            d->duplex = ret;
        }
    }
    
    return ret;
}

/**
 * Determina si la copia terminó (ambos lados cerraron y buffers vacíos)
 */
static bool
copy_is_done(struct socks5 *s) {
    // Si algún fd es inválido, terminamos
    if (s->client_fd == -1 || s->origin_fd == -1) {
        return true;
    }
    
    // Terminamos cuando ambos lados cerraron (OP_NOOP) y no hay datos pendientes
    bool client_closed = (s->client.copy.duplex == OP_NOOP);
    bool origin_closed = (s->orig.copy.duplex == OP_NOOP);
    bool no_client_data = !buffer_can_read(&s->read_buffer);
    bool no_origin_data = !buffer_can_read(&s->write_buffer);
    
    return client_closed && origin_closed && no_client_data && no_origin_data;
}

void
copy_init(const unsigned state, struct selector_key *key) {
    (void)state;
    
    struct socks5 *s = ATTACHMENT(key);
    
    // Inicializar estructuras de copy
    s->client.copy.fd = &s->client_fd;
    s->client.copy.rb = &s->read_buffer;
    s->client.copy.wb = &s->write_buffer;
    s->client.copy.duplex = OP_READ;
    
    s->orig.copy.fd = &s->origin_fd;
    s->orig.copy.rb = &s->write_buffer;
    s->orig.copy.wb = &s->read_buffer;
    s->orig.copy.duplex = OP_READ;
    
    // Configurar intereses: leer de ambos lados
    selector_set_interest(key->s, s->client_fd, OP_READ);
    selector_set_interest(key->s, s->origin_fd, OP_READ);
}

unsigned
copy_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct copy *d;
    buffer *rb;
    int *fd_src, *fd_dst;
    
    // Determinar de qué fd estamos leyendo
    if (key->fd == s->client_fd) {
        d = &s->client.copy;
        rb = d->rb;
        fd_src = &s->client_fd;
        fd_dst = &s->origin_fd;
    } else {
        d = &s->orig.copy;
        rb = d->rb;
        fd_src = &s->origin_fd;
        fd_dst = &s->client_fd;
    }
    
    unsigned ret = COPY;
    
    size_t nbytes;
    uint8_t *ptr = buffer_write_ptr(rb, &nbytes);
    ssize_t n = recv(*fd_src, ptr, nbytes, 0);
    
    if (n > 0) {
        // Datos recibidos
        buffer_write_adv(rb, n);
        
        // Activar escritura en el fd destino
        copy_compute_interests(key->s, d);
        
        // Calcular intereses del otro fd
        if (key->fd == s->client_fd) {
            copy_compute_interests(key->s, &s->orig.copy);
        } else {
            copy_compute_interests(key->s, &s->client.copy);
        }
        
    } else if (n == 0) {
        // EOF - El lado remoto cerró su escritura
        
        // Cerrar lectura de este fd
        shutdown(*fd_src, SHUT_RD);
        
        // Si no hay datos pendientes en el buffer, cerrar escritura del otro fd
        if (!buffer_can_read(rb)) {
            shutdown(*fd_dst, SHUT_WR);
        }
        
        // Actualizar intereses: ya no podemos leer de este fd
        d->duplex = OP_NOOP;
        selector_set_interest(key->s, *fd_src, OP_NOOP);
        
        // Actualizar intereses del otro fd
        if (key->fd == s->client_fd) {
            copy_compute_interests(key->s, &s->orig.copy);
        } else {
            copy_compute_interests(key->s, &s->client.copy);
        }
        
        // Verificar si terminamos
        if (copy_is_done(s)) {
            ret = DONE;
        }
        
    } else {
        // Error en recv
        ret = ERROR;
    }
    
    return ret;
}

unsigned
copy_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct copy *d;
    buffer *wb;
    int *fd_dst;
    
    // Determinar a qué fd estamos escribiendo
    if (key->fd == s->client_fd) {
        d = &s->client.copy;
        wb = d->wb;
        fd_dst = &s->client_fd;
    } else {
        d = &s->orig.copy;
        wb = d->wb;
        fd_dst = &s->origin_fd;
    }
    
    unsigned ret = COPY;
    
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(wb, &nbytes);
    ssize_t n = send(*fd_dst, ptr, nbytes, MSG_NOSIGNAL);
    
    if (n > 0) {
        // Datos enviados
        buffer_read_adv(wb, n);
        
        // Actualizar intereses
        copy_compute_interests(key->s, d);
        
        // Actualizar intereses del otro fd (solo si no está cerrado)
        if (key->fd == s->client_fd) {
            if (s->orig.copy.duplex != OP_NOOP) {
                copy_compute_interests(key->s, &s->orig.copy);
            }
        } else {
            if (s->client.copy.duplex != OP_NOOP) {
                copy_compute_interests(key->s, &s->client.copy);
            }
        }
        
        // Verificar si terminamos
        if (copy_is_done(s)) {
            ret = DONE;
        }
        
    } else {
        // Error en send
        ret = ERROR;
    }
    
    return ret;
}

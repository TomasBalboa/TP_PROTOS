#ifndef COPY_H_
#define COPY_H_

#include <stdint.h>
#include <stdbool.h>

#include "selector.h"
#include "buffer.h"

/**
 * Estado de copia para un fd (usado tanto para client como origin)
 */
struct copy {
    /** buffers para cada dirección */
    int    *fd;
    buffer *rb, *wb;
    /** intereses en el selector para cada fd */
    fd_interest duplex;
};

/**
 * Inicializa el estado COPY para una conexión SOCKS5
 * 
 * @param state   Estado actual (no usado)
 * @param key     Clave del selector
 */
void copy_init(const unsigned state, struct selector_key *key);

/**
 * Handler de lectura para el estado COPY
 * Lee datos de un fd y los escribe en el buffer correspondiente
 * 
 * @param key  Clave del selector
 * @return     Próximo estado (COPY, DONE o ERROR)
 */
unsigned copy_read(struct selector_key *key);

/**
 * Handler de escritura para el estado COPY
 * Escribe datos del buffer al fd correspondiente
 * 
 * @param key  Clave del selector
 * @return     Próximo estado (COPY, DONE o ERROR)
 */
unsigned copy_write(struct selector_key *key);

#endif

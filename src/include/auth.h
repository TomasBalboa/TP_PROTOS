#ifndef AUTH_H_
#define AUTH_H_

#include "selector.h"

/**
 * Handlers de estado AUTH_READ y AUTH_WRITE
 * (Siguen el mismo patrón que hello.h)
 */

void     auth_read_init(const unsigned state, struct selector_key *key);
unsigned auth_read(struct selector_key *key);
void     auth_read_close(const unsigned state, struct selector_key *key);
unsigned auth_write(struct selector_key *key);

#endif
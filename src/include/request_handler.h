#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H

#include "selector.h"

void request_init(const unsigned state, struct selector_key *key);
void request_close(const unsigned state, struct selector_key *key);
unsigned request_write_error_response(struct selector_key *key);
unsigned request_try_connect(struct selector_key *key);
unsigned request_resolving_init_do(const unsigned state, struct selector_key *key);
void request_resolving_init(const unsigned state, struct selector_key *key);
unsigned request_resolving_block_ready(struct selector_key *key);
unsigned request_read(struct selector_key *key);
unsigned request_write(struct selector_key *key);
unsigned request_connecting_write(struct selector_key *key);

#endif // REQUEST_HANDLER_H

// hello.h (nuevo)
#ifndef HELLO_STATE_H_
#define HELLO_STATE_H_

#include "selector.h"   // o donde esté struct selector_key

void     hello_read_init(const unsigned state, struct selector_key *key);
unsigned hello_read     (struct selector_key *key);
void     hello_read_close(const unsigned state, struct selector_key *key);
unsigned hello_write    (struct selector_key *key);

#endif

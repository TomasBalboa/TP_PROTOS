#ifndef SOCKS5NIO_H_25C415046151205A
#define SOCKS5NIO_H_25C415046151205A

#include "selector.h"

void socksv5_passive_accept(struct selector_key *key);
void socksv5_pool_destroy(void);

#endif
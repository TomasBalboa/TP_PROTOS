#ifndef MANAGMENT_COMMAND_H
#define MANAGMENT_COMMAND_H


#include "selector.h"
// Aquí van las definiciones y declaraciones relacionadas con los comandos de gestión

unsigned mgmt_command_read(struct selector_key *key);

unsigned mgmt_command_write(struct selector_key *key);

void mgmt_command_read_init(const unsigned state, struct selector_key *key);



#endif // MANAGMENT_COMMAND_H

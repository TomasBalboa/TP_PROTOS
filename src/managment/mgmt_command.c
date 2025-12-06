#include "../include/managment/managment.h"
#include "../include/managment/mgmt_command.h"
#include "selector.h"

void mgmt_command_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    (void)key;
}

unsigned mgmt_command_read(struct selector_key *key) {
    (void)key;
    return MANAGMENT_CLOSED;
}

unsigned mgmt_command_write(struct selector_key *key) {
    (void)key;
    return MANAGMENT_CLOSED;
}

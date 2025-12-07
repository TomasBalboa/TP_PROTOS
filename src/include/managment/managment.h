#ifndef MANAGMENT_H
#define MANAGMENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "logging.h"
#include "metrics.h"
#include "buffer.h"
#include "stm.h"
#include "auth_parser.h"
#include "managment/mgmt_command_parser.h"

#define MGMT_BUFFER_SIZE 4096

enum managment_state{

    MANAGMENT_AUTH_READ = 0,
    MANAGMENT_AUTH_WRITE,
    MANAGMENT_REQUEST_READ,
    MANAGMENT_REQUEST_WRITE,
    MANAGMENT_CLOSED,
    MANAGMENT_ERROR
}; 

typedef struct mgmt_client{
    struct state_machine stm;

    union{
        struct auth_parser auth;  // Parser compartido para auth (RFC 1929)
        struct mgmt_command_parser request; // parser de comandos de management
    }mgmt_parser;

    int client_fd;
    bool closed; 
    bool authenticated;
    bool is_admin;  // Si el usuario tiene privilegios de admin (NUEVO)

    struct buffer client_buffer;
    struct buffer origin_buffer;

    uint8_t buff_client[MGMT_BUFFER_SIZE];
    uint8_t buff_origin[MGMT_BUFFER_SIZE];

    mgmt_command current_command; // El comando que se esta llevando a cabo.

} mgmt_client;


/*
Función para aceptar conexiones de managment
*/

void managment_passive_accept(struct selector_key *key);

#endif // MANAGMENT_H

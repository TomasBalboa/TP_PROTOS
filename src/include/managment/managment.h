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
        auth_parser auth;
        //mgmt_command_parser request; //A implementar
    }mgmt_parser;

    int client_fd;
    bool closed; 
    bool authenticated;

    struct buffer client_buffer;
    struct buffer origin_buffer;

    uint8_t buff_client[MGMT_BUFFER_SIZE];
    uint8_t buff_origin[MGMT_BUFFER_SIZE];

    //mgmt_command current_command; //El comando que se esta llevando a cabo.

} mgmt_client;


/*
Función para aceptar conexiones de managment
*/

void managment_passive_accept(struct selector_key *key);

#endif // MANAGMENT_H

#ifndef TPROTOS_SOCKS5_H
#define TPROTOS_SOCKS5_H

// Aquí van las definiciones y declaraciones necesarias para el protocolo SOCKS5
#include <stdbool.h>
#include <sys/socket.h>
#include <netdb.h>
#include "selector.h"
#include "stm.h"
#include "buffer.h"

#define BUFFER_SIZE 32768 // 32 KB

//Conseguir la información del cliente SOCKS5 desde la key 
#define CLIENT (key) ((struct_client_session *)(key)->data)

//Estructura que representa cada conexión de cliente SOCKS5
typedef struct struct_client_session {
    struct state_machine stm; // Máquina de estados para la conexión
    int client_fd;            // File descriptor del cliente
    int target_fd;            // File descriptor del servidor destino

    char username[65];      // Nombre de usuario para autenticación
    bool authenticated;       // Indica si el cliente está autenticado


    struct buffer client_buffer; // Buffer para datos del cliente
    uint8_t client_buffer_data[BUFFER_SIZE];
    struct buffer target_buffer; // Buffer para datos del servidor destino
    uint8_t target_buffer_data[BUFFER_SIZE];

    struct addrinfo *origin_addrinfo; //Usado para resolver direcciones destino
    struct addrinfo *current_addrinfo; //Usado para iterar sobre las direcciones resueltas

    




} client_session;
    



#endif // TPROTOS_SOCKS5_H
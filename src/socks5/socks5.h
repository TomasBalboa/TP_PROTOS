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
#define CLIENT(key) ((struct_client_session *)(key)->data)

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

    struct sockaddr_storage client_addr; // Dirección del cliente
    union{

        struct parser_request request_parser;
        struct parser_handshake handshake_parser;
        struct parser_auth auth_parser;
    }client;

    //fd_selector selector; // Selector para multiplexación de E/S (ver si lo terminamos usando)
    struct gaicb dns_req;
    char dns_port[6]; // Puerto destino en formato string
    char dns_host[256]; // Host destino en formato string
    bool is_registered; // Indica si el usuario está registrado en las metricas/logs
    bool connection_closed; // Indica si la conexión está cerrada
    //bool resolution_from_getaddrinfo; //Vemos si mas adelante lo necesitamos 

} client_session;

enum socks5_states {
    SOCKS5_READ_HANDSHAKE,
    SOCKS5_WRITE_HANDSHAKE,
    SOCKS5_READ_AUTH,
    SOCKS5_WRITE_AUTH,
    SOCKS5_READ_REQUEST,
    SOCKS5_DNS_REQUEST,
    SOCKS5_CONNECT_REQUEST, 
    SOCKS5_WRITE_REQUEST,
    SOCKS5_COPY,
    SOCKS5_ERROR_STATE,
    SOCKS5_DONE
};

void socks5_passive_accept(struct selector_key *key);

void socks5_close(struct selector_key *key);

selector_status register_origin_selector(struct selector_key *key, int origin_fd, struct client_data *data);
    



#endif // TPROTOS_SOCKS5_H
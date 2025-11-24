#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Constantes del protocolo SOCKSv5 - RFC 1928 */
#define SOCKS5_VERSION 0x05

/* Métodos de autenticación */
#define SOCKS5_AUTH_NONE     0x00
#define SOCKS5_AUTH_GSSAPI   0x01
#define SOCKS5_AUTH_USERPASS 0x02
#define SOCKS5_AUTH_NOMETHOD 0xFF

/* Comandos SOCKSv5 */
#define SOCKS5_CMD_CONNECT      0x01
#define SOCKS5_CMD_BIND         0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

/* Tipos de dirección */
#define SOCKS5_ATYPE_IPV4   0x01
#define SOCKS5_ATYPE_DOMAIN 0x03
#define SOCKS5_ATYPE_IPV6   0x04

/* Códigos de respuesta */
#define SOCKS5_REP_SUCCESS           0x00
#define SOCKS5_REP_GENERAL_FAILURE   0x01
#define SOCKS5_REP_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE    0x03
#define SOCKS5_REP_HOST_UNREACHABLE       0x04
#define SOCKS5_REP_CONNECTION_REFUSED     0x05
#define SOCKS5_REP_TTL_EXPIRED           0x06
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 0x08

/* Tamaños máximos */
#define SOCKS5_MAX_DOMAIN_LENGTH 255
#define SOCKS5_MAX_USERNAME_LENGTH 255
#define SOCKS5_MAX_PASSWORD_LENGTH 255

/* Estados de conexión */
typedef enum {
    SOCKS5_STATE_AUTH_NEGOTIATION,
    SOCKS5_STATE_AUTH_USERPASS,
    SOCKS5_STATE_REQUEST,
    SOCKS5_STATE_CONNECTING,
    SOCKS5_STATE_ESTABLISHED,
    SOCKS5_STATE_ERROR,
    SOCKS5_STATE_CLOSED
} socks5_state_t;

/* Estructura para request de conexión */
typedef struct {
    uint8_t version;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atype;
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
        struct {
            uint8_t length;
            char domain[SOCKS5_MAX_DOMAIN_LENGTH];
        } domain;
    } addr;
    uint16_t port;
} socks5_request_t;

/* Estructura para respuesta */
typedef struct {
    uint8_t version;
    uint8_t rep;
    uint8_t rsv;
    uint8_t atype;
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } bind_addr;
    uint16_t bind_port;
} socks5_response_t;

/* Credenciales de usuario */
typedef struct {
    char username[SOCKS5_MAX_USERNAME_LENGTH + 1];
    char password[SOCKS5_MAX_PASSWORD_LENGTH + 1];
} socks5_credentials_t;

/* Funciones principales */
int socks5_handle_auth_negotiation(int client_fd, uint8_t *methods, size_t method_count);
int socks5_handle_userpass_auth(int client_fd, socks5_credentials_t *creds);
int socks5_handle_request(int client_fd, socks5_request_t *request);
int socks5_send_response(int client_fd, uint8_t rep, struct sockaddr *bind_addr);
int socks5_establish_connection(const socks5_request_t *request, int *target_fd);

#endif /* SOCKS5_H */

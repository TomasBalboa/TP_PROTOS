#ifndef __CLIENT_UTILS_H__
#define __CLIENT_UTILS_H__

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#define AUP_VERSION 1
#define MAX_AUP_REQUEST_SIZE 513

/**
 * @brief crea socket y se conecta
 * @param host al que se conecte
 * @param service puerto a conectar
 * @return si sale bien, el fd del socket, si no, -1
 */
int client_open_socket(const char* host, const char* service);

/**
 * @brief cierra el socket (y la conexión)
 * @param fd el file descriptor del socket
 */
void client_close_socket(int fd);

/**
 * @brief envía credenciales de autenticación
 * @param fd el file descriptor del socket
 * @param uname nombre de usuario
 * @param pwd contraseña
 * @return true si autenticó, false si no
 */
bool client_authenticate(int fd, char* uname, char* pwd);

/**
 * @brief envía un comando al servidor de management
 * @param fd el file descriptor del socket
 * @param command código del comando (0-7)
 * @param payload datos del comando (puede ser NULL si no hay payload)
 * @param payload_len longitud del payload
 * @return true si se envió correctamente, false si no
 */
bool send_mgmt_command(int fd, uint8_t command, const char* payload, uint8_t payload_len);

/**
 * @brief recibe respuesta del servidor de management
 * @param fd el file descriptor del socket
 * @param response buffer donde guardar la respuesta (debe tener al menos 256 bytes)
 * @param response_len donde guardar la longitud de la respuesta
 * @return status de la respuesta (0=OK, otro=error)
 */
uint8_t recv_mgmt_response(int fd, char* response, size_t* response_len);

/**
 * @brief ejecuta un comando simple sin argumentos
 * @param fd el file descriptor del socket
 * @param cmd_code código del comando
 * @param success_msg mensaje a mostrar en caso de éxito
 * @return 1 si éxito, 0 si error
 */
int execute_simple_command(int fd, uint8_t cmd_code, const char* success_msg);

/**
 * @brief ejecuta un comando con argumentos
 * @param fd el file descriptor del socket
 * @param cmd_code código del comando
 * @param args array de argumentos (strings)
 * @param arg_count cantidad de argumentos
 * @param success_msg mensaje a mostrar en caso de éxito
 * @return 1 si éxito, 0 si error
 */
int execute_command_with_args(int fd, uint8_t cmd_code, const char** args, 
                               int arg_count, const char* success_msg);

#endif

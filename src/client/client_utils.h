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

#endif
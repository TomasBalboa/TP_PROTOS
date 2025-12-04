#ifndef _UTIL_H_
#define _UTIL_H_

#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>

const char* print_socket_address_with(const struct sockaddr* address, const char separator);
const char* print_socket_address(const struct sockaddr* address);

const char* print_family(int family);
const char* print_type(int socktype);
const char* print_protocol(int protocol);
const char* print_flags(int flags);
const char* print_address_port(int family, struct sockaddr* address);

// Determina si dos sockets son iguales (misma direccion y puerto)
int sock_addrs_equal(const struct sockaddr* addr1, const struct sockaddr* addr2);

#endif

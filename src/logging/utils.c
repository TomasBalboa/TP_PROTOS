#include "../include/utils.h"

#define ADDRSTR_BUFLEN 64
#define FLAGSTR_BUFLEN 64

const char* print_family(int family) {
    switch (family) {
        case AF_INET:
            return "IPv4";
        case AF_INET6:
            return "IPv6";
        case AF_UNIX:
            return "unix";
        case AF_UNSPEC:
            return "unspecified";
    }

    return "unknown";
}

const char* print_type(int socktype) {
    switch (socktype) {
        case SOCK_STREAM:
            return "stream";
        case SOCK_DGRAM:
            return "datagram";
        case SOCK_SEQPACKET:
            return "seqpacket";
        case SOCK_RAW:
            return "raw";
    }

    return "unknown";
}

const char* print_protocol(int protocol) {
    switch (protocol) {
        case 0:
            return "default";
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_RAW:
            return "raw";
    }

    return "unknown";
}

const char* print_flags(int flags) {
    static char buffer[FLAGSTR_BUFLEN];

    strcpy(buffer, "flags");
    if (flags == 0) {
        strcat(buffer, " 0");
    } else {
        if (flags & AI_PASSIVE)
            strcat(buffer, " passive");
        if (flags & AI_CANONNAME)
            strcat(buffer, " canon");
        if (flags & AI_NUMERICHOST)
            strcat(buffer, " numhost");
        if (flags & AI_NUMERICSERV)
            strcat(buffer, " numserv");
        if (flags & AI_V4MAPPED)
            strcat(buffer, " v4mapped");
        if (flags & AI_ALL)
            strcat(buffer, " all");
    }

    return buffer;
}

const char* print_address_port(int family, struct sockaddr* address) {
    if (address == NULL)
        return "unknown address";

    static char buffer[ADDRSTR_BUFLEN];
    char abuf[INET6_ADDRSTRLEN];
    const char* addr;
    if (family == AF_INET) {
        struct sockaddr_in* sinp;
        sinp = (struct sockaddr_in*)address;
        addr = inet_ntop(AF_INET, &sinp->sin_addr, abuf, INET_ADDRSTRLEN);
        if (addr == NULL)
            addr = "unknown";
        strcpy(buffer, addr);
        if (sinp->sin_port != 0) {
            sprintf(buffer + strlen(buffer), ": %d", ntohs(sinp->sin_port));
        }
    } else if (family == AF_INET6) {
        struct sockaddr_in6* sinp;
        sinp = (struct sockaddr_in6*)address;
        addr = inet_ntop(AF_INET6, &sinp->sin6_addr, abuf, INET6_ADDRSTRLEN);
        if (addr == NULL)
            addr = "unknown";
        strcpy(buffer, addr);
        if (sinp->sin6_port != 0)
            sprintf(buffer + strlen(buffer), ": %d", ntohs(sinp->sin6_port));
    } else
        strcpy(buffer, "unknown");
    return buffer;
}

const char* print_socket_address_with(const struct sockaddr* address, const char separator) {
    if (address == NULL)
        return "unknown address";

    static char buffer[ADDRSTR_BUFLEN];
    void* addr;
    in_port_t port;

    switch (address->sa_family) {
        case AF_INET:
            addr = &((struct sockaddr_in*)address)->sin_addr;
            port = ntohs(((struct sockaddr_in*)address)->sin_port);
            break;
        case AF_INET6:
            addr = &((struct sockaddr_in6*)address)->sin6_addr;
            port = ntohs(((struct sockaddr_in6*)address)->sin6_port);
            break;
        default:
            strcpy(buffer, "[unknown type]"); // Unhandled type
            return buffer;
    }

    // Convert binary to printable address
    if (inet_ntop(address->sa_family, addr, buffer, INET6_ADDRSTRLEN) == NULL)
        strcpy(buffer, "[invalid address]");

    sprintf(buffer + strlen(buffer), "%c%u", separator, port);
    return buffer;
}

const char* print_socket_address(const struct sockaddr* address) {
    return print_socket_address_with(address, ':');
}

int sock_addrs_equal(const struct sockaddr* addr1, const struct sockaddr* addr2) {
    if (addr1 == NULL || addr2 == NULL)
        return addr1 == addr2;
    else if (addr1->sa_family != addr2->sa_family)
        return 0;
    else if (addr1->sa_family == AF_INET) {
        struct sockaddr_in* ipv4addr1 = (struct sockaddr_in*)addr1;
        struct sockaddr_in* ipv4addr2 = (struct sockaddr_in*)addr2;
        return ipv4addr1->sin_addr.s_addr == ipv4addr2->sin_addr.s_addr && ipv4addr1->sin_port == ipv4addr2->sin_port;
    } else if (addr1->sa_family == AF_INET6) {
        struct sockaddr_in6* ipv6addr1 = (struct sockaddr_in6*)addr1;
        struct sockaddr_in6* ipv6addr2 = (struct sockaddr_in6*)addr2;
        return memcmp(&ipv6addr1->sin6_addr, &ipv6addr2->sin6_addr, sizeof(struct in6_addr)) == 0 && ipv6addr1->sin6_port == ipv6addr2->sin6_port;
    } else
        return 0;
}

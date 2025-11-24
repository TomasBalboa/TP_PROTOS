#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "args.h"
#include "selector.h"
#include "stm.h"
#include "netutils.h"

/* Variables globales para manejo de señales */
static volatile sig_atomic_t server_running = 1;
static struct socks5args server_args;
static fd_selector main_selector;

/* Prototipos de funciones */
static void signal_handler(int signum);
static int setup_signals(void);
static void cleanup_server(void);
static int create_and_bind_socket(const char *addr, unsigned short port);
static void accept_new_socks_connection(struct selector_key *key);
static void accept_new_mgmt_connection(struct selector_key *key);

int main(int argc, char *argv[]) {
    printf("SOCKSv5 Proxy Server - TP Especial 2025/2\n");
    printf("==========================================\n\n");

    /* Parsear argumentos usando tu implementación */
    parse_args(argc, argv, &server_args);

    /* Configurar manejadores de señales */
    if (setup_signals() != 0) {
        fprintf(stderr, "Error configurando manejadores de señales\n");
        exit(EXIT_FAILURE);
    }

    printf("Configuración:\n");
    printf("  Puerto SOCKS: %d en %s\n", server_args.socks_port, server_args.socks_addr);
    printf("  Puerto Management: %d en %s\n", server_args.mng_port, server_args.mng_addr);
    printf("  Disectors: %s\n", server_args.disectors_enabled ? "habilitados" : "deshabilitados");
    
    /* Mostrar usuarios configurados */
    printf("  Usuarios configurados: ");
    for (int i = 0; i < MAX_USERS && server_args.users[i].name != NULL; i++) {
        printf("%s ", server_args.users[i].name);
    }
    printf("\n\n");

    /* Inicializar el selector */
    struct selector_init selector_config = {
        .signal = SIGUSR1,
        .select_timeout = {
            .tv_sec = 10,
            .tv_nsec = 0,
        }
    };

    if (selector_init(&selector_config) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Error inicializando selector\n");
        exit(EXIT_FAILURE);
    }

    main_selector = selector_new(1024);
    if (main_selector == NULL) {
        fprintf(stderr, "Error creando selector principal\n");
        exit(EXIT_FAILURE);
    }

    /* Crear y configurar socket SOCKS */
    int socks_fd = create_and_bind_socket(server_args.socks_addr, server_args.socks_port);
    if (socks_fd < 0) {
        fprintf(stderr, "Error creando socket SOCKS\n");
        exit(EXIT_FAILURE);
    }

    if (listen(socks_fd, 20) < 0) {
        perror("listen socks");
        exit(EXIT_FAILURE);
    }

    /* Crear y configurar socket de management */
    int mgmt_fd = create_and_bind_socket(server_args.mng_addr, server_args.mng_port);
    if (mgmt_fd < 0) {
        fprintf(stderr, "Error creando socket management\n");
        exit(EXIT_FAILURE);
    }

    if (listen(mgmt_fd, 5) < 0) {
        perror("listen mgmt");
        exit(EXIT_FAILURE);
    }

    /* Configurar handlers para los listeners */
    const fd_handler socks_handler = {
        .handle_read = accept_new_socks_connection,
        .handle_write = NULL,
        .handle_close = NULL,
    };

    const fd_handler mgmt_handler = {
        .handle_read = accept_new_mgmt_connection, 
        .handle_write = NULL,
        .handle_close = NULL,
    };

    /* Registrar los listeners en el selector */
    if (selector_register(main_selector, socks_fd, &socks_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Error registrando socket SOCKS\n");
        exit(EXIT_FAILURE);
    }

    if (selector_register(main_selector, mgmt_fd, &mgmt_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Error registrando socket management\n");
        exit(EXIT_FAILURE);
    }

    printf("Servidor iniciado exitosamente!\n");
    printf("  - SOCKS proxy escuchando en %s:%d\n", server_args.socks_addr, server_args.socks_port);
    printf("  - Management interface en %s:%d\n", server_args.mng_addr, server_args.mng_port);
    printf("Presiona Ctrl+C para detener...\n\n");

    /* Event loop principal usando tu selector */
    while (server_running) {
        selector_status status = selector_select(main_selector);
        if (status != SELECTOR_SUCCESS) {
            if (server_running) { /* Solo reportar error si no estamos saliendo */
                fprintf(stderr, "Error en selector: %s\n", selector_error(status));
            }
            break;
        }
    }

    printf("\nCerrando servidor...\n");
    cleanup_server();
    
    return EXIT_SUCCESS;
}

static int create_and_bind_socket(const char *addr, unsigned short port) {
    int sock_fd;
    struct sockaddr_in server_addr;
    int opt = 1;

    /* Crear socket */
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return -1;
    }

    /* Configurar opciones del socket */
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sock_fd);
        return -1;
    }

    /* Configurar no bloqueante */
    if (selector_fd_set_nio(sock_fd) < 0) {
        fprintf(stderr, "Error configurando socket no bloqueante\n");
        close(sock_fd);
        return -1;
    }

    /* Configurar dirección */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (strcmp(addr, "0.0.0.0") == 0) {
        server_addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, addr, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Dirección IP inválida: %s\n", addr);
        close(sock_fd);
        return -1;
    }

    /* Bind */
    if (bind(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

static void accept_new_socks_connection(struct selector_key *key) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd;

    client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            perror("accept socks");
        }
        return;
    }

    /* Configurar no bloqueante */
    if (selector_fd_set_nio(client_fd) < 0) {
        fprintf(stderr, "Error configurando cliente no bloqueante\n");
        close(client_fd);
        return;
    }

    /* Log de nueva conexión */
    char client_str[SOCKADDR_TO_HUMAN_MIN];
    sockaddr_to_human(client_str, sizeof(client_str), (struct sockaddr *)&client_addr);
    printf("Nueva conexión SOCKS desde: %s\n", client_str);

    /* TODO: Registrar cliente en el selector con handlers SOCKSv5 */
    /* TODO: Inicializar state machine para el cliente */
    
    /* Por ahora solo cerramos la conexión */
    printf("Cerrando conexión (SOCKSv5 no implementado aún)\n");
    close(client_fd);
}

static void accept_new_mgmt_connection(struct selector_key *key) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd;

    client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            perror("accept mgmt");
        }
        return;
    }

    /* Log de nueva conexión */
    char client_str[SOCKADDR_TO_HUMAN_MIN];
    sockaddr_to_human(client_str, sizeof(client_str), (struct sockaddr *)&client_addr);
    printf("Nueva conexión Management desde: %s\n", client_str);

    /* TODO: Implementar protocolo de management */
    
    /* Por ahora enviamos mensaje simple y cerramos */
    const char *welcome = "SOCKS5D Management Interface v1.0\nNo implementado aún.\n";
    write(client_fd, welcome, strlen(welcome));
    close(client_fd);
}

static void signal_handler(int signum) {
    switch (signum) {
        case SIGTERM:
        case SIGINT:
            printf("\nSeñal %d recibida, cerrando servidor...\n", signum);
            server_running = 0;
            break;
        case SIGHUP:
            printf("Recargando configuración... (no implementado)\n");
            break;
    }
}

static int setup_signals(void) {
    struct sigaction sa;
    
    /* Configurar manejador para SIGTERM, SIGINT y SIGHUP */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGTERM, &sa, NULL) == -1 ||
        sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGHUP, &sa, NULL) == -1) {
        perror("sigaction");
        return -1;
    }
    
    /* Ignorar SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
    
    return 0;
}

static void cleanup_server(void) {
    printf("Limpiando recursos...\n");
    
    if (main_selector != NULL) {
        selector_destroy(main_selector);
    }
    
    selector_close();
    printf("Servidor cerrado exitosamente.\n");
}

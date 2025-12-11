/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de línea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarán en éste hilo.
 *
 * Se descargará en otro hilos las operaciones bloqueantes (resolución de
 * DNS utilizando getaddrinfo), pero toda esa complejidad está oculta en
 * el selector.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "selector.h"
#include "socks5nio.h"
#include "resolver_pool.h"
#include "./include/logging.h"
#include "./include/args.h"
#include "./include/metrics.h"
#include "./include/user_validation.h"
#include "./include/managment/managment.h"
#include "./include/users.h"
#include "./include/auth_config.h"


static bool done = false;

// Variable global para acceso a args desde otros módulos
struct socks5args args;

static void
sigterm_handler(const int signal) {
    logf(LOG_INFO, "signal %d, cleaning up and exiting", signal);
    done = true;
}

int
main(const int argc, char **argv) {
    parse_args(argc, argv, &args);

    if (!auth_config_init()) {
        fprintf(stderr, "Error initializing auth_config module. Aborting.\n");
        exit(1);
    }

    metricsInit();
    users_init();  // Inicializar sistema de usuarios

    // Crear usuarios especificados por línea de comandos con -u
    for(int i = 0; i < MAX_USERS && args.users[i].name != NULL; i++) {
        if(create_user(args.users[i].name, args.users[i].pass, false)) {
            logf(LOG_OUTPUT, "Usuario añadido: %s", args.users[i].name);
        } else {
            logf(LOG_WARNING, "No se pudo añadir usuario: %s (puede que ya exista)", args.users[i].name);
        }
    }

    // no tenemos nada que leer de stdin
    close(0);

    int server = -1;

    const char       *err_msg = NULL;
    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;
    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };
    if(0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    // Inicializar thread pool de resolución DNS
    resolver_pool_init();

    selector = selector_new(1024);
    if(selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }

    loggerInit(selector,"",stdout);
    loggerSetLevel(LOG_DEBUG);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(args.socks_port);
    
    // Convertir la dirección de string a formato de red
    if(inet_pton(AF_INET, args.socks_addr, &addr.sin_addr) <= 0) {
        err_msg = "invalid SOCKS address";
        goto finally;
    }

     server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(server < 0) {
        err_msg = "unable to create socket";
        goto finally;
    }

    logf(LOG_OUTPUT, "Escuchando puerto TCP %d en %s", args.socks_port, args.socks_addr);

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    if(bind(server, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        err_msg = "unable to bind socket";
        goto finally;
    }

    if (listen(server, 20) < 0) {
        err_msg = "unable to listen";
        goto finally;
    }

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    if(selector_fd_set_nio(server) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }
    
    const struct fd_handler socksv5 = {
        .handle_read       = socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    ss = selector_register(selector, server, &socksv5,
                                              OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }
    
    // ===== MANAGEMENT SOCKET =====
    // Crear socket de management
    const int mgmt_server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(mgmt_server < 0) {
        err_msg = "unable to create management socket";
        goto finally;
    }

    setsockopt(mgmt_server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    struct sockaddr_in mgmt_addr;
    memset(&mgmt_addr, 0, sizeof(mgmt_addr));
    mgmt_addr.sin_family      = AF_INET;
    mgmt_addr.sin_port        = htons(args.mng_port);
    
    if(inet_pton(AF_INET, args.mng_addr, &mgmt_addr.sin_addr) <= 0) {
        err_msg = "invalid management address";
        goto finally;
    }

    if(bind(mgmt_server, (struct sockaddr*) &mgmt_addr, sizeof(mgmt_addr)) < 0) {
        err_msg = "unable to bind management socket";
        goto finally;
    }

    if (listen(mgmt_server, 20) < 0) {
        err_msg = "unable to listen on management socket";
        goto finally;
    }

    if(selector_fd_set_nio(mgmt_server) == -1) {
        err_msg = "getting management socket flags";
        goto finally;
    }

    const struct fd_handler mgmt_handler = {
        .handle_read       = managment_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL,
    };
    
    ss = selector_register(selector, mgmt_server, &mgmt_handler, OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering management fd";
        goto finally;
    }
    
    logf(LOG_OUTPUT, "Management server listening on %s:%d", args.mng_addr, args.mng_port);
    logf(LOG_OUTPUT, "Default admin user: %s / %s", DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD);
    
    // usuarios adicionales que creo con -u 
    size_t total_users = users_get_count();
    if(total_users > 1) {
        logf(LOG_OUTPUT, "Additional users created: %zu", total_users - 1);
    }
    // ===== END MANAGEMENT SOCKET =====
    
    for(;!done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    if(err_msg == NULL) {
        err_msg = "closing";
    }

    int ret = 0;
finally:
    loggerFinalize();
    if(ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "": err_msg,
                                  ss == SELECTOR_IO
                                      ? strerror(errno)
                                      : selector_error(ss));
        ret = 2;
    } else if(err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if(selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    // Destruir thread pool de resolución DNS
    resolver_pool_destroy();

    socksv5_pool_destroy();

    if(server >= 0) {
        close(server);
    }
    auth_config_cleanup();
    return ret;
}

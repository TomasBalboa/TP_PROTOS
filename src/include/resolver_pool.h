#ifndef RESOLVER_POOL_H
#define RESOLVER_POOL_H

#include <netdb.h>
#include <pthread.h>
#include "selector.h"

/**
 * Job de resolución DNS asíncrona.
 * Se envía a un thread worker y se notifica cuando completa.
 */
struct resolution_job {
    // Datos de entrada
    char hostname[256];
    char port[6];
    struct addrinfo hints;
    
    // Datos de salida
    struct addrinfo *result;
    int error_code;  // 0 = success, != 0 = error de getaddrinfo
    
    // Sincronización (protegido por mutex)
    int completed;              // 0 = en progreso, 1 = completado
    pthread_mutex_t mutex;      // Protege el campo completed
    
    // Referencia al selector y fd para notificación
    fd_selector selector;
    int client_fd;
    
    // Referencia al objeto socks5 (con reference counting)
    void *socks5_ref;
};

/**
 * Inicializa el thread pool de resolución DNS.
 * Debe llamarse antes de usar el sistema de resolución.
 */
void resolver_pool_init(void);

/**
 * Envía un job de resolución al thread pool.
 * Retorna 0 si se encoló correctamente, -1 en caso de error.
 */
int resolver_pool_submit(struct resolution_job *job);

/**
 * Destruye el thread pool y espera que terminen todos los workers.
 * Debe llamarse al finalizar el programa.
 */
void resolver_pool_destroy(void);

#endif // RESOLVER_POOL_H

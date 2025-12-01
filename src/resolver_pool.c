/**
 * resolver_pool.c - Thread pool para resolución DNS asíncrona
 */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include "resolver_pool.h"
#include "selector.h"

#define MAX_WORKERS 10
#define JOB_QUEUE_SIZE 100

// Cola de trabajos thread-safe
struct job_queue {
    struct resolution_job *jobs[JOB_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    int shutdown;
};

static struct job_queue job_queue;
static pthread_t worker_threads[MAX_WORKERS];
static int worker_count = 0;
static pthread_once_t pool_init_once = PTHREAD_ONCE_INIT;

/**
 * Función que ejecuta cada worker thread.
 * Toma jobs de la cola y ejecuta getaddrinfo() de forma bloqueante.
 */
static void *
resolver_worker(void *arg) {
    (void)arg;
    
    // Bloquear todas las señales en este thread
    // Solo el thread principal debe manejar señales
    sigset_t set;
    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    
    while (1) {
        pthread_mutex_lock(&job_queue.mutex);
        
        // Esperar por trabajo
        while (job_queue.count == 0 && !job_queue.shutdown) {
            pthread_cond_wait(&job_queue.not_empty, &job_queue.mutex);
        }
        
        if (job_queue.shutdown) {
            pthread_mutex_unlock(&job_queue.mutex);
            break;
        }
        
        // Obtener job de la cola
        struct resolution_job *job = job_queue.jobs[job_queue.head];
        job_queue.head = (job_queue.head + 1) % JOB_QUEUE_SIZE;
        job_queue.count--;
        
        pthread_cond_signal(&job_queue.not_full);
        pthread_mutex_unlock(&job_queue.mutex);
        
        // Ejecutar resolución DNS (BLOQUEANTE - pero en thread separado)
        job->error_code = getaddrinfo(job->hostname, job->port, 
                                      &job->hints, &job->result);
        
        // Marcar como completado ANTES de notificar (protegido por mutex)
        pthread_mutex_lock(&job->mutex);
        job->completed = 1;
        pthread_mutex_unlock(&job->mutex);
        
        // Notificar al selector principal
        if (job->selector != NULL && job->client_fd >= 0) {
            // Interrumpir pselect() para que procese el resultado
            selector_notify_block(job->selector, job->client_fd);
        }
        
        // NO liberar el job aquí - lo hace el handler on_block_ready
    }
    
    return NULL;
}

/**
 * Inicializa el pool de workers (llamado una sola vez).
 */
static void
resolver_pool_init_once(void) {
    memset(&job_queue, 0, sizeof(job_queue));
    pthread_mutex_init(&job_queue.mutex, NULL);
    pthread_cond_init(&job_queue.not_empty, NULL);
    pthread_cond_init(&job_queue.not_full, NULL);
    job_queue.shutdown = 0;
    
    // Crear workers
    for (int i = 0; i < MAX_WORKERS; i++) {
        if (pthread_create(&worker_threads[i], NULL, resolver_worker, NULL) == 0) {
            worker_count++;
        }
    }
}

void
resolver_pool_init(void) {
    pthread_once(&pool_init_once, resolver_pool_init_once);
}

/**
 * Encola un job de resolución en el thread pool.
 * Retorna 0 si se encoló correctamente, -1 en caso de error o timeout.
 */
int
resolver_pool_submit(struct resolution_job *job) {
    pthread_mutex_lock(&job_queue.mutex);
    
    // Esperar si la cola está llena (con timeout para evitar deadlock)
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 5;  // 5 segundos timeout
    
    while (job_queue.count >= JOB_QUEUE_SIZE && !job_queue.shutdown) {
        int ret = pthread_cond_timedwait(&job_queue.not_full, 
                                         &job_queue.mutex, &timeout);
        if (ret == ETIMEDOUT || ret != 0) {
            pthread_mutex_unlock(&job_queue.mutex);
            return -1;  // Timeout o error
        }
    }
    
    if (job_queue.shutdown) {
        pthread_mutex_unlock(&job_queue.mutex);
        return -1;
    }
    
    // Encolar job
    job_queue.jobs[job_queue.tail] = job;
    job_queue.tail = (job_queue.tail + 1) % JOB_QUEUE_SIZE;
    job_queue.count++;
    
    pthread_cond_signal(&job_queue.not_empty);
    pthread_mutex_unlock(&job_queue.mutex);
    
    return 0;
}

/**
 * Destruye el thread pool y espera que terminen todos los workers.
 */
void
resolver_pool_destroy(void) {
    pthread_mutex_lock(&job_queue.mutex);
    job_queue.shutdown = 1;
    pthread_cond_broadcast(&job_queue.not_empty);
    pthread_mutex_unlock(&job_queue.mutex);
    
    // Esperar que terminen todos los workers
    for (int i = 0; i < worker_count; i++) {
        pthread_join(worker_threads[i], NULL);
    }
    
    pthread_mutex_destroy(&job_queue.mutex);
    pthread_cond_destroy(&job_queue.not_empty);
    pthread_cond_destroy(&job_queue.not_full);
}

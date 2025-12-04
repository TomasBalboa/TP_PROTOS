#ifndef __METRICS_H__
#define __METRICS_H__

#include <stdlib.h>
#include <time.h>
#include <string.h>

typedef struct {
    size_t current_connections;
    size_t total_connections;
    size_t max_connections;
    size_t bytes_sent;
    size_t bytes_recieved;
    time_t uptime;
    size_t dns_queries;
} metrics_t;

/**
 * @brief Setea el contador de estadísticas
 */
void metricsInit();

/**
 * @brief Registra que se generó una nueva conexión: 
 * total_connections++, current_connections++, max_connections = ( current_connections > max_connections ) ? current_connections : max_connections
 */
void metrics_login();

/**
 * @brief Registra que se cerró una sesión:
 * current_connections--
 */
void metrics_logout();

/**
 * @brief Registra una transferencia de bytes:
 * metrics.bytes_sent += bytes_sent, metrics.bytes_recieved += bytes_recieved
 * @param bytes_sent Bytes que envió el cliente
 * @param bytes_recieved Bytes que recivió el cliente
 */
void metrics_update(size_t bytes_sent, size_t bytes_recieved);

/**
 * @brief Obtiene las estadísticas al momento
 * @param metrics Puntero a la estructura donde se desea que se carguen las estadísticas
 */
void metrics_getter(metrics_t* metrics);

/**
 * @brief Registra una query de DNS
 */
void metrics_query_dns();

/**
 * @brief Obtiene en segundos el tiempo de vida del servidor
 * @return El tiempo de vida del servidor en segundos
 */
time_t metrics_get_uptime();

#endif

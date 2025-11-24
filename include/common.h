#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>

/* Configuración general */
#define MAX_CONNECTIONS 1000
#define BUFFER_SIZE 8192
#define DEFAULT_SOCKS_PORT 1080
#define DEFAULT_ADMIN_PORT 9090

/* Estructura para configuración del servidor */
typedef struct {
    uint16_t socks_port;
    uint16_t admin_port;
    char *bind_address;
    int max_connections;
    int connection_timeout;
    bool enable_logging;
    char *log_file;
    char *users_file;
} server_config_t;

/* Estructura para métricas */
typedef struct {
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t bytes_transferred;
    uint64_t failed_connections;
    struct timeval start_time;
    struct timeval last_connection;
} server_metrics_t;

/* Buffer circular para I/O eficiente */
typedef struct {
    char *data;
    size_t size;
    size_t read_pos;
    size_t write_pos;
    size_t available;
} circular_buffer_t;

/* Estados de conexión */
typedef enum {
    CONN_STATE_INIT,
    CONN_STATE_SOCKS_AUTH,
    CONN_STATE_SOCKS_REQUEST,
    CONN_STATE_CONNECTING,
    CONN_STATE_ESTABLISHED,
    CONN_STATE_CLOSING,
    CONN_STATE_CLOSED
} connection_state_t;

/* Información de una conexión activa */
typedef struct connection {
    int client_fd;
    int target_fd;
    connection_state_t state;
    
    circular_buffer_t client_buffer;
    circular_buffer_t target_buffer;
    
    char client_ip[INET6_ADDRSTRLEN];
    uint16_t client_port;
    char target_host[256];
    uint16_t target_port;
    
    char username[256];
    struct timeval connect_time;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    
    struct connection *next;
} connection_t;

/* Funciones de utilidades comunes */
int create_server_socket(const char *address, uint16_t port);
int set_nonblocking(int fd);
int set_socket_options(int fd);

/* Gestión de buffers circulares */
circular_buffer_t* buffer_create(size_t size);
void buffer_destroy(circular_buffer_t *buffer);
ssize_t buffer_read_from_fd(circular_buffer_t *buffer, int fd);
ssize_t buffer_write_to_fd(circular_buffer_t *buffer, int fd);
size_t buffer_available_read(const circular_buffer_t *buffer);
size_t buffer_available_write(const circular_buffer_t *buffer);

/* Gestión de conexiones */
connection_t* connection_create(int client_fd);
void connection_destroy(connection_t *conn);
void connection_list_add(connection_t **head, connection_t *conn);
void connection_list_remove(connection_t **head, connection_t *conn);

/* Logging */
typedef enum {
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
} log_level_t;

void log_message(log_level_t level, const char *format, ...);
void log_connection(const connection_t *conn, const char *event);

/* Configuración */
int config_load(const char *filename, server_config_t *config);
void config_free(server_config_t *config);

#endif /* COMMON_H */

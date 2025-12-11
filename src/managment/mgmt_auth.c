#include "managment/mgmt_auth.h"
#include "managment/managment.h"
#include "logging.h"
#include "user_validation.h"
#include "auth.h"
#include "users.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

/**
 * Valida las credenciales usando el módulo compartido.
 * Esta función delega la validación a validate_user_credentials() 
 * que verifica contra args.users[].
 */
bool try_to_authenticate(const char *username, const char *password, bool *is_admin) {
    return validate_user_credentials(username, password, is_admin);
}

/**
 * Inicializa el parser de autenticación cuando entramos al estado AUTH_READ.
 * Esta función es llamada automáticamente por la FSM (on_arrival).
 */
void mgmt_auth_init(const unsigned state, struct selector_key *key) {
    (void)state;  // No usado, pero requerido por la firma de on_arrival
    
    mgmt_client *data = (mgmt_client *)key->data;
    
    // Inicializar el parser de autenticación compartido (auth_parser)
    auth_parser_init(&data->mgmt_parser.auth);
    
    logf(LOG_DEBUG, "[MGMT_AUTH] fd=%d: Iniciando autenticación", data->client_fd);
}

/**
 * Handler de lectura para MANAGEMENT_AUTH_READ.
 * Lee y parsea las credenciales usando auth_parser (compartido con SOCKS5).
 */
unsigned mgmt_auth_read(struct selector_key *key) {
    mgmt_client *data = (mgmt_client *)key->data;
    struct auth_parser *p = &data->mgmt_parser.auth;
    
    size_t read_limit;
    ssize_t read_count;
    uint8_t *read_buffer = buffer_write_ptr(&data->client_buffer, &read_limit);
    
    read_count = recv(data->client_fd, read_buffer, read_limit, 0);
    
    if (read_count <= 0) {
        if (read_count == 0) {
            logf(LOG_INFO, "[MGMT_AUTH] fd=%d: Cliente cerró conexión", data->client_fd);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            logf(LOG_ERROR, "[MGMT_AUTH] fd=%d: Error en recv: %s", 
                 data->client_fd, strerror(errno));
        }
        return MANAGMENT_ERROR;
    }
    
    logf(LOG_DEBUG, "[MGMT_AUTH] fd=%d: Leídos %zd bytes", data->client_fd, read_count);
    
    buffer_write_adv(&data->client_buffer, read_count);
    
    // Parsear con la función original auth_consume()
    bool errored = false;
    enum auth_state st = auth_consume(&data->client_buffer, p, &errored);
    
    if (auth_is_done(st)) {
        logf(LOG_DEBUG, "[MGMT_AUTH] fd=%d: Parser completado. User='%s'", 
             data->client_fd, p->username);
        
        if (auth_has_error(st) || errored) {
            logf(LOG_WARNING, "[MGMT_AUTH] fd=%d: Error en parser", data->client_fd);
            return MANAGMENT_ERROR;
        }
        
        // Validar credenciales usando módulo compartido
        bool is_admin = false;
        bool authenticated = try_to_authenticate(p->username, p->password, &is_admin);

        // Actualizar estado del cliente
        data->authenticated = authenticated;
        data->is_admin = is_admin;

        if (authenticated) {
            logf(LOG_INFO, "[MGMT_AUTH] fd=%d: Usuario '%s' autenticado %s",
                 data->client_fd, p->username, is_admin ? "(admin)" : "");
            // Registrar autenticación exitosa de management
            users_add_access_log(p->username, "management auth success");
        } else {
            logf(LOG_WARNING, "[MGMT_AUTH] fd=%d: Autenticación fallida para '%s'",
                 data->client_fd, p->username);
            // Registrar intento fallido de management (opcional)
            users_add_access_log(p->username, "management auth failed");
        }

        // Construir respuesta usando la función original auth_marshall_response()
        if (auth_marshall_response(&data->origin_buffer, authenticated) == -1) {
            logf(LOG_ERROR, "[MGMT_AUTH] fd=%d: Error construyendo respuesta", data->client_fd);
            return MANAGMENT_ERROR;
        }
        
        // Cambiar interés del selector a OP_WRITE
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            logf(LOG_ERROR, "[MGMT_AUTH] fd=%d: Error cambiando a OP_WRITE", data->client_fd);
            return MANAGMENT_ERROR;
        }
        
        return MANAGMENT_AUTH_WRITE;
    }
    
    return MANAGMENT_AUTH_READ;
}

/**
 * Handler de escritura para MANAGEMENT_AUTH_WRITE.
 * Envía la respuesta de autenticación al cliente.
 */
unsigned mgmt_auth_write(struct selector_key *key) {
    mgmt_client *data = (mgmt_client *)key->data;
    
    size_t write_limit;
    ssize_t write_count;
    uint8_t *write_buffer = buffer_read_ptr(&data->origin_buffer, &write_limit);
    
    write_count = send(data->client_fd, write_buffer, write_limit, MSG_NOSIGNAL);
    
    if (write_count <= 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            logf(LOG_ERROR, "[MGMT_AUTH] fd=%d: Error en send: %s", 
                 data->client_fd, strerror(errno));
            return MANAGMENT_ERROR;
        }
        return MANAGMENT_AUTH_WRITE;  // Reintentar
    }
    
    logf(LOG_DEBUG, "[MGMT_AUTH] fd=%d: Enviados %zd bytes", data->client_fd, write_count);
    
    buffer_read_adv(&data->origin_buffer, write_count);
    
    // Verificar que se envió todo
    if (buffer_can_read(&data->origin_buffer)) {
        logf(LOG_WARNING, "[MGMT_AUTH] fd=%d: Respuesta incompleta", data->client_fd);
        return MANAGMENT_ERROR;
    }
    
    // Verificar que el parser no tiene errores
    if (auth_has_error(data->mgmt_parser.auth.state)) {
        logf(LOG_WARNING, "[MGMT_AUTH] fd=%d: Parser tiene error", data->client_fd);
        return MANAGMENT_ERROR;
    }
    
    // Verificar que el usuario está autenticado
    if (!data->authenticated) {
        logf(LOG_WARNING, "[MGMT_AUTH] fd=%d: Usuario no autenticado", data->client_fd);
        return MANAGMENT_ERROR;
    }
    
    // Cambiar interés a OP_READ para recibir comandos
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        logf(LOG_ERROR, "[MGMT_AUTH] fd=%d: Error cambiando a OP_READ", data->client_fd);
        return MANAGMENT_ERROR;
    }
    
    logf(LOG_INFO, "[MGMT_AUTH] fd=%d: Autenticación completada exitosamente", data->client_fd);
    
    return MANAGMENT_REQUEST_READ;
}

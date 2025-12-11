#include "managment/managment.h"
#include "managment/mgmt_command.h"
#include "managment/mgmt_command_parser.h"
#include "auth_config.h"
#include "users.h"
#include "metrics.h"
#include "selector.h"
#include <string.h>
#include <sys/socket.h>

// Procesa el comando ya parseado y construye la respuesta en origin_buffer
static bool mgmt_process_command(mgmt_command_parser *parser,
                                 struct buffer *response_buffer,
                                 bool is_admin);

// Handlers por comando
typedef bool (*mgmt_command_handler)(mgmt_command_parser *parser,
                                     struct buffer *response_buffer);

static bool mgmt_add_user_handler(mgmt_command_parser *parser,
                                  struct buffer *response_buffer);
static bool mgmt_delete_user_handler(mgmt_command_parser *parser,
                                     struct buffer *response_buffer);
static bool mgmt_list_users_handler(mgmt_command_parser *parser,
                                    struct buffer *response_buffer);
static bool mgmt_stats_handler(mgmt_command_parser *parser,
                               struct buffer *response_buffer);

static bool mgmt_change_role_handler(mgmt_command_parser *parser,
                                     struct buffer *response_buffer);
static bool mgmt_set_default_auth_handler(mgmt_command_parser *parser,
                                          struct buffer *response_buffer);
static bool mgmt_get_default_auth_handler(mgmt_command_parser *parser,
                                          struct buffer *response_buffer);
static bool mgmt_user_activity_handler(mgmt_command_parser *parser,
                                       struct buffer *response_buffer);
static bool mgmt_change_password_handler(mgmt_command_parser *parser,
                                         struct buffer *response_buffer);

// Tabla de handlers indexada por enum mgmt_command
static mgmt_command_handler command_handlers[] = {
    mgmt_add_user_handler,    // MGMT_ADD_USER
    mgmt_delete_user_handler, // MGMT_DELETE_USER
    mgmt_list_users_handler,  // MGMT_LIST_USERS
    mgmt_stats_handler,       // MGMT_STATS
    mgmt_change_role_handler,       // MGMT_CHANGE_ROLE
    mgmt_set_default_auth_handler,  // MGMT_SET_DEFAULT_AUTH_METHOD
    mgmt_get_default_auth_handler,  // MGMT_GET_DEFAULT_AUTH_METHOD
    mgmt_user_activity_handler,     // MGMT_USER_ACTIVITY
    mgmt_change_password_handler,   // MGMT_CHANGE_PASSWORD
};

// Qué comandos requieren privilegios de admin
static bool needs_admin_privileges[] = {
    true,  // MGMT_ADD_USER
    true,  // MGMT_DELETE_USER
    false, // MGMT_LIST_USERS
    false, // MGMT_STATS
    true,  // MGMT_CHANGE_ROLE
    true,  // MGMT_SET_DEFAULT_AUTH_METHOD
    true,  // MGMT_GET_DEFAULT_AUTH_METHOD
    true,  // MGMT_USER_ACTIVITY
    true,  // MGMT_CHANGE_PASSWORD
};

void mgmt_command_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    mgmt_client *data = (mgmt_client *)key->data;

    // Cambiamos el union al parser de comandos
    mgmt_command_parser_init(&data->mgmt_parser.request);
}

unsigned mgmt_command_read(struct selector_key *key) {
    mgmt_client *data = (mgmt_client *)key->data;
    mgmt_command_parser *parser = &data->mgmt_parser.request;

    size_t read_limit;
    ssize_t read_count;
    uint8_t *buf = buffer_write_ptr(&data->client_buffer, &read_limit);

    read_count = recv(data->client_fd, buf, read_limit, 0);
    if (read_count <= 0) {
        return MANAGMENT_ERROR; // error o conexión cerrada
    }

    buffer_write_adv(&data->client_buffer, read_count);
    mgmt_command_parser_parse(parser, &data->client_buffer);

    if (mgmt_command_parser_is_done(parser)) {
        if (mgmt_command_parser_has_error(parser)) {
            return MANAGMENT_ERROR;
        }

        buffer_reset(&data->origin_buffer);

        if (!mgmt_process_command(parser, &data->origin_buffer, data->is_admin)) {
            return MANAGMENT_ERROR;
        }

        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return MANAGMENT_ERROR;
        }

        data->current_command = parser->command;
        return MANAGMENT_REQUEST_WRITE;
    }

    return MANAGMENT_REQUEST_READ;
}

unsigned mgmt_command_write(struct selector_key *key) {
    mgmt_client *data = (mgmt_client *)key->data;

    size_t write_limit;
    ssize_t write_count;
    uint8_t *buf = buffer_read_ptr(&data->origin_buffer, &write_limit);

    write_count = send(data->client_fd, buf, write_limit, MSG_NOSIGNAL);
    if (write_count <= 0) {
        return MANAGMENT_ERROR; // error o conexión cerrada
    }

    buffer_read_adv(&data->origin_buffer, write_count);

    if (buffer_can_read(&data->origin_buffer)) {
        return MANAGMENT_REQUEST_WRITE; // todavía queda por enviar
    }

    if (mgmt_command_parser_has_error(&data->mgmt_parser.request)) {
        return MANAGMENT_ERROR;
    }

    // Por simplicidad cerramos la conexión tras responder un comando.
    return MANAGMENT_CLOSED;
}


static bool mgmt_add_user_handler(mgmt_command_parser *parser,
                                  struct buffer *response_buffer) {
    if (parser->args_count != 2) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "add_user: expected 2 args");
    }

    const char *username = (const char *)parser->args[0];
    const char *password = (const char *)parser->args[1];

    if (exists_user(username)) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "add_user: user already exists");
    }

    if (create_user(username, password, false)) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_OK,
                                                  "add_user: user added");
    }

    return mgmt_command_parser_build_response(parser, response_buffer,
                                              MGMT_STATUS_SERVER_ERROR,
                                              "add_user: failed to add user");
}

static bool mgmt_delete_user_handler(mgmt_command_parser *parser,
                                     struct buffer *response_buffer) {
    if (parser->args_count != 1) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "delete_user: expected 1 arg");
    }

    const char *username = (const char *)parser->args[0];

    if (!exists_user(username)) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "delete_user: user not found");
    }

    if (delete_user(username)) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_OK,
                                                  "delete_user: user deleted");
    }

    return mgmt_command_parser_build_response(parser, response_buffer,
                                              MGMT_STATUS_SERVER_ERROR,
                                              "delete_user: failed to delete user");
}

static bool mgmt_list_users_handler(mgmt_command_parser *parser,
                                    struct buffer *response_buffer) {
    (void)parser;

    // Encabezado con cantidad de usuarios
    int user_count = (int)users_get_count();
    char header[64];
    int header_len = snprintf(header, sizeof(header), "users count: %d\n", user_count);

    if (!mgmt_command_parser_build_response(parser, response_buffer,
                                            MGMT_STATUS_OK, NULL)) {
        return false;
    }

    size_t available;
    uint8_t *ptr = buffer_write_ptr(response_buffer, &available);
    if ((size_t)header_len > available) {
        return false;
    }
    memcpy(ptr, header, header_len);
    buffer_write_adv(response_buffer, header_len);

    // Volcar usernames como texto adicional
    ptr = buffer_write_ptr(response_buffer, &available);
    size_t written = users_dump_usernames(ptr, available);
    if (written == 0) {
        return false;
    }
    buffer_write_adv(response_buffer, written);

    return true;
}

static bool mgmt_stats_handler(mgmt_command_parser *parser,
                               struct buffer *response_buffer) {
    (void)parser;

    metrics_t m;
    metrics_getter(&m);

    char response[256];
    int len = snprintf(response, sizeof(response),
                       "Current connections: %zu\n"
                       "Total connections: %zu\n"
                       "Max connections: %zu\n"
                       "Bytes sent: %zu\n"
                       "Bytes received: %zu\n"
                       "DNS queries: %zu\n"
                       "Uptime (s): %ld\n",
                       m.current_connections,
                       m.total_connections,
                       m.max_connections,
                       m.bytes_sent,
                       m.bytes_recieved,
                       m.dns_queries,
                       (long)metrics_get_uptime());

    if (len < 0) {
        return false;
    }

    if (!mgmt_command_parser_build_response(parser, response_buffer,
                                            MGMT_STATUS_OK, NULL)) {
        return false;
    }

    size_t available;
    uint8_t *ptr = buffer_write_ptr(response_buffer, &available);
    if ((size_t)len > available) {
        return false;
    }
    memcpy(ptr, response, len);
    buffer_write_adv(response_buffer, len);

    return true;
}


static bool mgmt_process_command(mgmt_command_parser *parser,
                                 struct buffer *resp,
                                 bool is_admin) {
    size_t n = sizeof command_handlers / sizeof command_handlers[0];
    if ((size_t)parser->command >= n) {
        return false; // enum fuera de rango
    }

    if (needs_admin_privileges[parser->command] && !is_admin) {
        return mgmt_command_parser_build_response(parser, resp,
                                                  MGMT_STATUS_FORBIDDEN,
                                                  "command requires admin privileges");
    }

    return command_handlers[parser->command](parser, resp);
}

static bool mgmt_set_default_auth_handler(mgmt_command_parser *parser,
                                          struct buffer *response_buffer) {
    if (parser->args_count != 1) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "set_default_auth: expected 1 arg");
    }

    const char *method_str = (const char *)parser->args[0];
    enum socks5_auth_method method;

    if (strcmp(method_str, "no_auth") == 0) {
        method = SOCKS5_AUTH_NO_AUTH;
    } else if (strcmp(method_str, "username_password") == 0) {
        method = SOCKS5_AUTH_USER_PASS;
    } else {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "set_default_auth: method must be 'no_auth' or 'username_password'");
    }

    if (!auth_config_set_default(method)) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_SERVER_ERROR,
                                                  "set_default_auth: failed");
    }

    return mgmt_command_parser_build_response(parser, response_buffer,
                                              MGMT_STATUS_OK,
                                              "set_default_auth: ok");
}

static bool mgmt_get_default_auth_handler(mgmt_command_parser *parser,
                                          struct buffer *response_buffer) {
    if (parser->args_count != 0) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "get_default_auth: expected 0 args");
    }

    enum socks5_auth_method method = auth_config_get_default();
    const char *method_str = (method == SOCKS5_AUTH_NO_AUTH)
                             ? "no_auth"
                             : "username_password";

    char body[64];
    int len = snprintf(body, sizeof(body),
                       "Default auth method: %s\n", method_str);
    if (len < 0) return false;

    if (!mgmt_command_parser_build_response(parser, response_buffer,
                                            MGMT_STATUS_OK, NULL)) {
        return false;
    }

    size_t available;
    uint8_t *ptr = buffer_write_ptr(response_buffer, &available);
    if ((size_t)len > available) return false;

    memcpy(ptr, body, len);
    buffer_write_adv(response_buffer, len);

    return true;
}

static bool mgmt_change_role_handler(mgmt_command_parser *parser,
                                     struct buffer *response_buffer) {
    if (parser->args_count != 2) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "change_role: expected 2 args");
    }

    const char *username = (const char *)parser->args[0];
    const char *role_str = (const char *)parser->args[1];

    if (!exists_user(username)) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "change_role: user not found");
    }

    bool make_admin;
    if (strcmp(role_str, "admin") == 0) {
        make_admin = true;
    } else if (strcmp(role_str, "user") == 0) {
        make_admin = false;
    } else {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "change_role: role must be 'admin' or 'user'");
    }

    if (!users_change_role(username, make_admin)) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_SERVER_ERROR,
                                                  "change_role: failed");
    }

    return mgmt_command_parser_build_response(parser, response_buffer,
                                              MGMT_STATUS_OK,
                                              "change_role: role changed");
}


static bool mgmt_user_activity_handler(mgmt_command_parser *parser,
                                       struct buffer *response_buffer) {
    if (parser->args_count != 1) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "user_activity: expected 1 argument");
    }

    const char *username = (const char *)parser->args[0];

    if (!exists_user(username)) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_SERVER_ERROR,
                                                  "user_activity: user not found");
    }

    struct access_log_t logs[MAX_ACCESS_LOGS];
    size_t total_logs = get_user_access_history(username, logs, MAX_ACCESS_LOGS);

    if (total_logs == 0) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_SERVER_ERROR,
                                                  "user_activity: no activity logs found for user");
    }

    if (!mgmt_command_parser_build_response(parser, response_buffer,
                                            MGMT_STATUS_OK, NULL)) {
        return false;
    }

    char response[1024];
    int response_len = 0;

    response_len += snprintf(response + response_len,
                             sizeof(response) - response_len,
                             "Access history for %s (%zu records):\n",
                             username, total_logs);

    for (size_t i = 0; i < total_logs && response_len < (int)sizeof(response) - 1; i++) {
        char time_str[64];
        time_t timestamp = (time_t)logs[i].timestamp;
        struct tm *tm_info = localtime(&timestamp);

        if (tm_info != NULL) {
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            response_len += snprintf(response + response_len,
                                     sizeof(response) - response_len,
                                     "%s - %s\n",
                                     time_str, logs[i].ip_or_site);
        } else {
            response_len += snprintf(response + response_len,
                                     sizeof(response) - response_len,
                                     "[Invalid date] - %s\n",
                                     logs[i].ip_or_site);
        }
    }

    size_t available;
    uint8_t *ptr = buffer_write_ptr(response_buffer, &available);
    if ((size_t)response_len > available) {
        return false;
    }

    memcpy(ptr, response, response_len);
    buffer_write_adv(response_buffer, response_len);

    return true;
}

static bool mgmt_change_password_handler(mgmt_command_parser *parser,
                                         struct buffer *response_buffer) {
    if (parser->args_count != 2) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "change_password: expected 2 args");
    }

    const char *username = (const char *)parser->args[0];
    const char *new_password = (const char *)parser->args[1];

    if (!exists_user(username)) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_INVALID_ARGS,
                                                  "change_password: user not found");
    }

    if (!users_change_password(username, new_password)) {
        return mgmt_command_parser_build_response(parser, response_buffer,
                                                  MGMT_STATUS_SERVER_ERROR,
                                                  "change_password: failed");
    }

    return mgmt_command_parser_build_response(parser, response_buffer,
                                              MGMT_STATUS_OK,
                                              "change_password: password changed");
}






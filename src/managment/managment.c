#include "managment.h"
#include "selector.h"
#include "stm.h"
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>

// Prototipos de handlers que vamos a implementar luego (los ponemos aca para que compile)
void mgmt_auth_init(const unsigned state, struct selector_key *key);
unsigned mgmt_auth_read(struct selector_key *key);
unsigned mgmt_auth_write(struct selector_key *key);

void mgmt_command_read_init(const unsigned state, struct selector_key *key);
unsigned mgmt_command_read(struct selector_key *key);
unsigned mgmt_command_write(struct selector_key *key);

// Función placeholder para estados sin lógica específica
static void mgmt_nothing(const unsigned state, struct selector_key *key) {
    (void)state;
    (void)key;
}

// Tabla de estados de la FSM de management
static const struct state_definition managment_states[] = {
    {
        .state        = MANAGMENT_AUTH_READ,
        .on_arrival   = mgmt_auth_init,
        .on_read_ready = mgmt_auth_read,
    },
    {
        .state        = MANAGMENT_AUTH_WRITE,
        .on_write_ready = mgmt_auth_write,
    },
    {
        .state        = MANAGMENT_REQUEST_READ,
        .on_arrival   = mgmt_command_read_init,
        .on_read_ready = mgmt_command_read,
    },
    {
        .state        = MANAGMENT_REQUEST_WRITE,
        .on_arrival   = mgmt_nothing,
        .on_write_ready = mgmt_command_write,
    },
    {
        .state        = MANAGMENT_CLOSED,
        .on_arrival   = mgmt_nothing,
    },
    {
        .state        = MANAGMENT_ERROR,
        .on_arrival   = mgmt_nothing,
    },
};

// Forward de handlers top‑level
static void mgmt_read(struct selector_key *key);
static void mgmt_write(struct selector_key *key);
static void mgmt_block(struct selector_key *key);
static void mgmt_close(struct selector_key *key);
static void mgmt_close_connection(struct selector_key *key);

// Handler de fd para el selector
static struct fd_handler managment_handler = {
    .handle_read  = mgmt_read,
    .handle_write = mgmt_write,
    .handle_block = mgmt_block,
    .handle_close = mgmt_close,
};

// Cierre lógico de la conexión de management
static void mgmt_close_connection(struct selector_key *key) {
    mgmt_client *client = (mgmt_client *) key->data;
    if (client == NULL || client->closed) {
        return;
    }

    client->closed = true;

    if (client->client_fd >= 0) {
        selector_unregister_fd(key->s, client->client_fd);
        close(client->client_fd);
        client->client_fd = -1;
    }

    free(client);
}

// Handler de close del selector
static void mgmt_close(struct selector_key *key) {
    struct state_machine *stm = &((mgmt_client *)key->data)->stm;
    stm_handler_close(stm, key);
    mgmt_close_connection(key);
}

// Handler de read top‑level: delega en la FSM
static void mgmt_read(struct selector_key *key) {
    mgmt_client *client = (mgmt_client *) key->data;
    struct state_machine *stm = &client->stm;
    enum managment_state st = (enum managment_state) stm_handler_read(stm, key);

    if (st == MANAGMENT_CLOSED || st == MANAGMENT_ERROR) {
        mgmt_close_connection(key);
    }
}

// Handler de write top‑level: delega en la FSM
static void mgmt_write(struct selector_key *key) {
    mgmt_client *client = (mgmt_client *) key->data;
    struct state_machine *stm = &client->stm;
    enum managment_state st = (enum managment_state) stm_handler_write(stm, key);

    if (st == MANAGMENT_CLOSED || st == MANAGMENT_ERROR) {
        mgmt_close_connection(key);
    }
}

// Handler de block (por ahora no usás bloqueantes en management,
// pero lo dejamos por simetría)
static void mgmt_block(struct selector_key *key) {
    mgmt_client *client = (mgmt_client *) key->data;
    struct state_machine *stm = &client->stm;
    enum managment_state st = (enum managment_state) stm_handler_block(stm, key);

    if (st == MANAGMENT_CLOSED || st == MANAGMENT_ERROR) {
        mgmt_close_connection(key);
    }
}

/*
 * Acepta una nueva conexión de management.
 * Esta función es la que vas a registrar como handle_read en el socket pasivo
 * de management en main.c (similar a socksv5_passive_accept).
 */
void managment_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    const int client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        perror("accept(management)");
        return;
    }

    if (selector_fd_set_nio(client_fd) == -1) {
        close(client_fd);
        return;
    }

    mgmt_client *client = calloc(1, sizeof(mgmt_client));
    if (client == NULL) {
        perror("calloc(mgmt_client)");
        close(client_fd);
        return;
    }

    client->client_fd    = client_fd;
    client->closed       = false;
    client->authenticated = false;

    // Inicializar buffers
    buffer_init(&client->client_buffer, MGMT_BUFFER_SIZE, client->buff_client);
    buffer_init(&client->origin_buffer, MGMT_BUFFER_SIZE, client->buff_origin);

    // Inicializar FSM
    client->stm.initial   = MANAGMENT_AUTH_READ;
    client->stm.max_state = MANAGMENT_ERROR;
    client->stm.states    = managment_states;
    stm_init(&client->stm);

    // Registrar en selector
    const selector_status ss = selector_register(key->s, client_fd,
                                                 &managment_handler,
                                                 OP_READ, client);
    if (ss != SELECTOR_SUCCESS) {
        perror("selector_register(management)");
        close(client_fd);
        free(client);
        return;
    }

    logf(LOG_INFO, "[MGMT] nueva conexión de management fd=%d", client_fd);
}




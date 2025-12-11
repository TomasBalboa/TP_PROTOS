#ifndef USERS_H
#define USERS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "args.h"

/* Límites de usuario */
#define MAX_USERNAME_LENGTH 64
#define MAX_PASSWORD_LENGTH 64
#define MAX_U          128

/* Credenciales por defecto del administrador */
#define DEFAULT_ADMIN_USERNAME "admin"
#define DEFAULT_ADMIN_PASSWORD "0000"

/* Máximo de logs de acceso */
#define MAX_ACCESS_LOGS 16

/* Registro de acceso */
struct access_log_t {
    uint64_t timestamp;
    char ip_or_site[64]; // tamaño razonable para host/ip
};

/* Representación interna de un usuario */
struct user_t {
    char name[MAX_USERNAME_LENGTH + 1];   /* null-terminated */
    char pass[MAX_PASSWORD_LENGTH + 1];   /* null-terminated */
    bool is_admin;

    struct access_log_t access_logs[MAX_ACCESS_LOGS];
    size_t access_log_count;
    size_t current_access_log_index;
};



/**
 * Inicializa el sistema de usuarios.
 * 
 * Puede:
 *  - Cargar un usuario admin por defecto.
 *  - Inicializar la tabla interna vacía.
 *  - (Opcional) copiar los usuarios definidos en args.users[].
 */
void users_init(void);

/**
 * Crea un nuevo usuario.
 * @param username nombre de usuario
 * @param password contraseña
 * @param is_admin true si es administrador
 * @return true si se creó correctamente, false si no hay espacio
 *         o el usuario ya existe.
 */
bool create_user(const char *username, const char *password, bool is_admin);

/**
 * Elimina un usuario existente.
 * @param username nombre de usuario a borrar
 * @return true si se eliminó, false si no existía.
 */
bool delete_user(const char *username);

/**
 * Indica si un usuario existe.
 */
bool exists_user(const char *username);

/**
 * Indica si un usuario es admin.
 * @return true si existe y es admin, false en caso contrario.
 */
bool users_is_admin(const char *username);

/**
 * Valida credenciales contra la tabla interna de usuarios.
 * @param username usuario
 * @param password contraseña
 * @param is_admin opcional, setea true si el usuario es admin
 * @return true si usuario existe y la contraseña coincide
 */
bool users_authenticate(const char *username, const char *password, bool *is_admin);

/**
 * @return cantidad de usuarios actualmente registrados.
 */
size_t users_get_count(void);

/**
 * Vuelca todos los usernames en un buffer destino, separados por '\n'
 * o el formato que prefieras.
 * 
 * @param dst buffer destino
 * @param dst_len tamaño del buffer
 * @return cantidad de bytes escritos en dst.
 */
size_t users_dump_usernames(uint8_t *dst, size_t dst_len);

/**
 * Cambia el rol (admin / no admin) de un usuario existente.
 * @param username nombre de usuario
 * @param is_admin nuevo valor de admin
 * @return true si se cambió, false si el usuario no existe.
 */
bool users_change_role(const char *username, bool is_admin);

/**
 * Cambia la contraseña de un usuario existente.
 * @param username nombre de usuario
 * @param new_password nueva contraseña
 * @return true si se cambió, false si el usuario no existe o contraseña inválida.
 */
bool users_change_password(const char *username, const char *new_password);

void users_add_access_log(const char *username, const char *ip_or_site);

size_t get_user_access_history(const char *username,
                               struct access_log_t *logs,
                               size_t max_logs);

#endif /* USERS_H */

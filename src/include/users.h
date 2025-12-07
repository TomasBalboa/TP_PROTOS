#ifndef USERS_H
#define USERS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Límites de usuario */
#define MAX_USERNAME_LENGTH 64
#define MAX_PASSWORD_LENGTH 64
#define MAX_USERS          128

/* Credenciales por defecto del administrador */
#define DEFAULT_ADMIN_USERNAME "admin"
#define DEFAULT_ADMIN_PASSWORD "1234"

/* Representación interna de un usuario */
struct user_t {
    char name[MAX_USERNAME_LENGTH + 1];   /* null-terminated */
    char pass[MAX_PASSWORD_LENGTH + 1];   /* null-terminated */
    bool is_admin;
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

#endif /* USERS_H */

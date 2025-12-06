#ifndef USER_VALIDATION_H
#define USER_VALIDATION_H

#include <stdbool.h>

// Forward declaration
struct users;

/**
 * user_validation.h - Módulo compartido de validación de usuarios
 * 
 * Este módulo centraliza la validación de credenciales para:
 * - Autenticación SOCKS5 (RFC 1929)
 * - Autenticación de Management
 * 
 * Ambos protocolos validan contra la misma base de usuarios (args.users[])
 */

/**
 * Valida las credenciales de un usuario contra la base de datos de usuarios.
 * 
 * @param username Nombre de usuario a validar
 * @param password Contraseña a validar
 * @param is_admin Puntero donde se guardará si el usuario tiene privilegios de admin.
 *                 Puede ser NULL si no interesa esta información.
 * @return true si las credenciales son válidas, false en caso contrario
 * 
 * Ejemplo de uso:
 *   bool is_admin;
 *   if (validate_user_credentials("admin", "password123", &is_admin)) {
 *       printf("Usuario autenticado. Es admin: %s\n", is_admin ? "sí" : "no");
 *   }
 */
bool validate_user_credentials(const char *username, const char *password, bool *is_admin);

/**
 * Inicializa el módulo de validación de usuarios.
 * Debe ser llamada una vez al inicio del programa, después de parse_args().
 * 
 * @param users Array de usuarios desde args.users
 * @param max_users Número máximo de usuarios en el array
 */
void user_validation_init(const struct users *users, int max_users);

/**
 * Obtiene el número de usuarios registrados.
 * 
 * @return Número de usuarios registrados en el sistema
 */
int get_registered_users_count(void);

#endif // USER_VALIDATION_H

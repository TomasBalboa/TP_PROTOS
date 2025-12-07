#include "user_validation.h"
#include "args.h"
#include "logging.h"
#include <string.h>
#include <stdlib.h>

/**
 * user_validation.c - Implementación del módulo de validación de usuarios
 * 
 * Este módulo valida credenciales contra args.users[] para:
 * - Autenticación SOCKS5 (RFC 1929)
 * - Autenticación de protocolo de Management
 */

/**
 * Inicializa el módulo de validación.
 * Guarda una referencia a la estructura de usuarios.
 */
void user_validation_init(const struct users *users, int max_users) {
    (void)users;      // No usado directamente, accedemos via global_args
    (void)max_users;  // No usado directamente
    
    // La referencia a args se obtiene externamente
    // Este módulo accede a args globales directamente
    
    logf(LOG_INFO, "[USER_VALIDATION] Módulo inicializado%s", "");
}

/**
 * Valida las credenciales de un usuario.
 * 
 * Busca el usuario en args.users[] y compara credenciales.
 * El primer usuario del array se considera administrador.
 * 
 * @param username Usuario a validar
 * @param password Contraseña a validar
 * @param is_admin Puntero donde guardar si es admin (puede ser NULL)
 * @return true si las credenciales son válidas
 */
bool validate_user_credentials(const char *username, const char *password, bool *is_admin) {
    // Validación de parámetros
    if (username == NULL || password == NULL) {
        logf(LOG_WARNING, "[USER_VALIDATION] Parametros NULL en validacion%s", "");
        return false;
    }
    
    if (strlen(username) == 0 || strlen(password) == 0) {
        logf(LOG_WARNING, "[USER_VALIDATION] Credenciales vacias%s", "");
        return false;
    }
    
    // Acceder a args global
    extern struct socks5args args;
    
    // Buscar usuario en la lista
    for (int i = 0; i < MAX_USERS; i++) {
        // Si llegamos a un slot vacío, terminamos la búsqueda
        if (args.users[i].name == NULL || args.users[i].name[0] == '\0') {
            break;
        }
        
        // Comparar username y password
        if (strcmp(username, args.users[i].name) == 0 &&
            strcmp(password, args.users[i].pass) == 0) {
            
            // Credenciales válidas
            logf(LOG_INFO, "[USER_VALIDATION] Usuario '%s' autenticado (indice %d)", 
                 username, i);
            
            // El primer usuario (índice 0) es considerado administrador
            if (is_admin != NULL) {
                *is_admin = (i == 0);
            }
            
            return true;
        }
    }
    
    // Usuario no encontrado o credenciales incorrectas
    logf(LOG_WARNING, "[USER_VALIDATION] Autenticacion fallida para usuario '%s'", username);
    return false;
}

/**
 * Obtiene el número de usuarios registrados.
 */
int get_registered_users_count(void) {
    extern struct socks5args args;
    
    int count = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if (args.users[i].name != NULL && args.users[i].name[0] != '\0') {
            count++;
        } else {
            break;
        }
    }
    
    return count;
}

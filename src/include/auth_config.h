#ifndef AUTH_CONFIG_H
#define AUTH_CONFIG_H

#include <stdbool.h>
#include "socks5nio.h"  // o el header donde tengas enum auth_methods

// Inicializa el módulo de configuración de auth (locks, valor inicial).
bool auth_config_init(void);

// Libera recursos del módulo de configuración de auth.
void auth_config_cleanup(void);

// Devuelve el método de autenticación por defecto (NO_AUTH o USER_PASS).
enum socks5_auth_method auth_config_get_default(void);

// Setea el método de autenticación por defecto.
// Acepta SOLO NO_AUTH y USER_PASS.
// Devuelve true si se pudo setear, false si el método es inválido o hubo error.
bool auth_config_set_default(enum socks5_auth_method method);

#endif

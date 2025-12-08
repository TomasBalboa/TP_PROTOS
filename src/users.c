#include "users.h"

#include <string.h>

static struct user_t users[MAX_U];
static size_t user_count = 0;
static int hash_table[MAX_U]; 

static void initialize_hash_table(void) {
    for (int i = 0; i < MAX_U; i++) {
        hash_table[i] = -1;
    }
}

static unsigned int hash_function(const char *str) {
    unsigned int hash = 0;
    while (*str) {
        hash = (hash * 31u) + (unsigned char)(*str++);
    }
    return hash % MAX_U;
}

// Devuelve índice de usuario o -1 si no existe
static int find_user(const char *username) {
    if (username == NULL || *username == '\0') {
        return -1;
    }

    unsigned int index    = hash_function(username);
    unsigned int original = index;

    do {
        if (hash_table[index] == -1) {
            return -1;  // casillero vacío → no existe
        }

        int user_idx = hash_table[index];
        if (user_idx >= 0 && user_idx < (int)user_count &&
            strcmp(users[user_idx].name, username) == 0) {
            return user_idx;
        }

        index = (index + 1) % MAX_U;
    } while (index != original);

    return -1;
}

static bool validate_length(const char *s) {
    if (s == NULL) return false;
    size_t len = strlen(s);
    return len > 0 && len <= MAX_USERNAME_LENGTH;
}

void users_init(void) {
    user_count = 0;
    initialize_hash_table();

    // Crear admin por defecto
    (void)create_user(DEFAULT_ADMIN_USERNAME,
                      DEFAULT_ADMIN_PASSWORD,
                      true);
}

bool create_user(const char *username, const char *password, bool is_admin) {
    if (user_count >= MAX_U) {
        return false;  // sin espacio
    }
    if (!validate_length(username) || !validate_length(password)) {
        return false;  // nombres/contraseñas vacíos o demasiado largos
    }
    if (find_user(username) != -1) {
        return false;  // ya existe
    }

    struct user_t u;

    strncpy(u.name, username, MAX_USERNAME_LENGTH);
    u.name[MAX_USERNAME_LENGTH] = '\0';
    // copiar password
    strncpy(u.pass, password, MAX_PASSWORD_LENGTH);
    u.pass[MAX_PASSWORD_LENGTH] = '\0';
    u.is_admin = is_admin;

    // insertar en array
    users[user_count] = u;

    // insertar en tabla hash
    unsigned int index = hash_function(username);
    while (hash_table[index] != -1) {
        index = (index + 1) % MAX_U;
    }
    hash_table[index] = (int)user_count;

    user_count++;
    return true;
}

bool delete_user(const char *username) {
    int user_idx = find_user(username);
    if (user_idx == -1) {
        return false;  // no existe
    }

    // borrar entrada en la tabla hash para este usuario
    unsigned int index = hash_function(users[user_idx].name);
    while (hash_table[index] != -1) {
        if (hash_table[index] == user_idx) {
            hash_table[index] = -1;
            break;
        }
        index = (index + 1) % MAX_U;
    }

    // si no es el último, swappear con el último
    if (user_idx != (int)user_count - 1) {
        char moved_name[MAX_USERNAME_LENGTH + 1];

        // guardar nombre del último usuario
        strncpy(moved_name, users[user_count - 1].name, MAX_USERNAME_LENGTH);
        moved_name[MAX_USERNAME_LENGTH] = '\0';

        // mover último usuario a la posición liberada
        users[user_idx] = users[user_count - 1];

        // actualizar tabla hash: encontrar entrada vieja del usuario movido
        unsigned int old_index = hash_function(moved_name);
        while (hash_table[old_index] != (int)user_count - 1) {
            old_index = (old_index + 1) % MAX_U;
        }
        // reasignar al nuevo índice
        hash_table[old_index] = user_idx;
    }

    user_count--;
    return true;
}

bool exists_user(const char *username) {
    return find_user(username) != -1;
}

bool users_is_admin(const char *username) {
    int user_idx = find_user(username);
    if (user_idx == -1) {
        return false;
    }
    return users[user_idx].is_admin;
}

bool users_authenticate(const char *username, const char *password, bool *is_admin) {
    int user_idx = find_user(username);
    if (user_idx == -1) {
        return false;
    }
    if (strcmp(users[user_idx].pass, password) != 0) {
        return false;
    }
    if (is_admin != NULL) {
        *is_admin = users[user_idx].is_admin;
    }
    return true;
}

size_t users_get_count(void) {
    return user_count;
}

size_t users_dump_usernames(uint8_t *dst, size_t dst_len) {
    if (dst == NULL || dst_len == 0) {
        return 0;
    }

    size_t written = 0;

    for (size_t i = 0; i < user_count; i++) {
        const char *name = users[i].name;
        size_t len = strlen(name);

        // nombre + '\n'
        if (written + len + 1 > dst_len) {
            break;
        }

        memcpy(dst + written, name, len);
        written += len;

        dst[written++] = '\n';
    }

    return written;
}

bool users_change_role(const char *username, bool is_admin) {
    int user_idx = find_user(username);
    if (user_idx == -1) {
        return false;  // no existe
    }

    users[user_idx].is_admin = is_admin;
    return true;
}



#include "./include/auth_config.h"
#include <pthread.h>

static enum socks5_auth_method default_auth_method = SOCKS5_AUTH_USER_PASS;
static pthread_rwlock_t default_auth_rwlock;

bool auth_config_init(void) {
    if (pthread_rwlock_init(&default_auth_rwlock, NULL) != 0) {
        return false;
    }
    default_auth_method = SOCKS5_AUTH_USER_PASS;   // valor inicial
    return true;
}

void auth_config_cleanup(void) {
    pthread_rwlock_destroy(&default_auth_rwlock);
}

bool auth_config_set_default(enum socks5_auth_method method) {
    if (method != SOCKS5_AUTH_NO_AUTH && method != SOCKS5_AUTH_USER_PASS) {
        return false;
    }

    if (pthread_rwlock_wrlock(&default_auth_rwlock) != 0) {
        return false;
    }

    default_auth_method = method;

    pthread_rwlock_unlock(&default_auth_rwlock);
    return true;
}

enum socks5_auth_method auth_config_get_default(void) {
    enum socks5_auth_method method;

    if (pthread_rwlock_rdlock(&default_auth_rwlock) != 0) {
        return SOCKS5_AUTH_USER_PASS; // fallback razonable
    }

    method = default_auth_method;

    pthread_rwlock_unlock(&default_auth_rwlock);
    return method;
}

#ifndef __CLIENT_UTILS_H__
#define __CLIENT_UTILS_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    const char* name;
    const char * summary;
    bool must_be_admin;
    uint8_t argc;
    const char* args;
    cmd_t command;
} console_cmd_t;

typedef int (*cmd_t) (int, char**);

/**
 * @brief Función que imprimiría los comandos posibles
 * @param none debería valer 0, representa la cantidad de argumentos
 * @param empty debería ser vacío, representa los argumentos
 * @return el retorno es irrelevante, da 1
 */
int cmd_print_help(int none, char** empty);

/**
 * @brief Función que lista los usuarios posibles
 * @param none debería valer 0, representa la cantidad de argumentos
 * @param empty debería ser vacío, representa los argumentos
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_list_users(int none, char** emtpy);

/**
 * @brief Función que imprime estadísticas
 * @param none debería valer 0, representa la cantidad de argumentos
 * @param empty debería ser vacío, representa los argumentos
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_print_metrics(int none, char** emtpy);

/**
 * @brief Función que registra un nuevo usuario
 * @param two debería valer 2, representa la cantidad de argumentos
 * @param args el primer string será el usuario, el segundo la contraseña
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_add_user(int two, char** args);

/**
 * @brief Función que cambia la contraseña de un usuario
 * @param two debería valer 2, representa la cantidad de argumentos
 * @param args el primer string será el usuario, el segundo la nueva contraseña
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_change_pwd(int two, char** args);

/**
 * @brief Función que borra un usuario
 * @param one debería valer 1, representa la cantidad de argumentos
 * @param user el usuario que se desea borrar
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_delete_user(int one, char** user);

/**
 * @brief Función que da o quita el permiso de admin a un usuario
 * @param two debería valer 2, representa la cantidad de argumentos
 * @param args el primer string será el usuario, el segundo el rol (admin o user)
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_change_role(int two, char** args);

/**
 * @brief Función que imprime la actividad de un usuario
 * @param one debería valer 1, representa la cantidad de argumentos
 * @param user el usuario al que se desea auditar
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_audit_user(int one, char** user);

/**
 * @brief Función que alterna el método de autenticación default entre user/password y no-auth
 * @param one debería valer 1, representa la cantidad de argumentos
 * @param method no_auth o username_password
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_set_default_auth(int one, char** method);

/**
 * @brief Función que retorna el método de autenticación default actual
 * @param one debería valer 1, representa la cantidad de argumentos
 * @param empty debería ser vacío, representa los argumentos
 * @return retorna 1 por user/password y 0 por no-auth 
 */
int cmd_get_default_auth(int none, char** empty);

#endif
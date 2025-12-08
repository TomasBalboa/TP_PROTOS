#ifndef __CLIENT_CMD_H__
#define __CLIENT_CMD_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef int (*cmd_t) (int, int, char**);

typedef struct {
    const char* name;
    const char * summary;
    bool must_be_admin;
    uint8_t argc;
    const char* args;
    cmd_t command;
} console_cmd_t;

#define CLIENT_CMD_SIZE 10

/**
 * @brief Función que imprimiría los comandos posibles
 * @param socket vincula con management
 * @param none debería valer 0, representa la cantidad de argumentos
 * @param empty debería ser vacío, representa los argumentos
 * @return el retorno es irrelevante, da 1
 */
int cmd_print_help(int socket, int none, char** empty);

/**
 * @brief Función que lista los usuarios posibles
 * @param socket vincula con management
 * @param none debería valer 0, representa la cantidad de argumentos
 * @param empty debería ser vacío, representa los argumentos
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_list_users(int socket, int none, char** emtpy);

/**
 * @brief Función que imprime estadísticas
 * @param socket vincula con management
 * @param none debería valer 0, representa la cantidad de argumentos
 * @param empty debería ser vacío, representa los argumentos
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_print_metrics(int socket, int none, char** empty);

/**
 * @brief Función que registra un nuevo usuario
 * @param socket vincula con management
 * @param two debería valer 2, representa la cantidad de argumentos
 * @param args el primer string será el usuario, el segundo la contraseña
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_add_user(int socket, int two, char** args);

/**
 * @brief Función que cambia la contraseña de un usuario
 * @param socket vincula con management
 * @param two debería valer 2, representa la cantidad de argumentos
 * @param args el primer string será el usuario, el segundo la nueva contraseña
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_change_pwd(int socket, int two, char** args);

/**
 * @brief Función que borra un usuario
 * @param socket vincula con management
 * @param one debería valer 1, representa la cantidad de argumentos
 * @param user el usuario que se desea borrar
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_delete_user(int socket, int one, char** user);

/**
 * @brief Función que da o quita el permiso de admin a un usuario
 * @param socket vincula con management
 * @param two debería valer 2, representa la cantidad de argumentos
 * @param args el primer string será el usuario, el segundo el rol (admin o user)
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_change_role(int socket, int two, char** args);

/**
 * @brief Función que imprime la actividad de un usuario
 * @param socket vincula con management
 * @param one debería valer 1, representa la cantidad de argumentos
 * @param user el usuario al que se desea auditar
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_audit_user(int socket, int one, char** user);

/**
 * @brief Función que alterna el método de autenticación default entre user/password y no-auth
 * @param socket vincula con management
 * @param one debería valer 1, representa la cantidad de argumentos
 * @param method no_auth o username_password
 * @return retorna 1 si se acepta, si no 0
 */
int cmd_set_default_auth(int socket, int one, char** method);

/**
 * @brief Función que retorna el método de autenticación default actual
 * @param socket vincula con management
 * @param one debería valer 1, representa la cantidad de argumentos
 * @param empty debería ser vacío, representa los argumentos
 * @return retorna 1 por user/password y 0 por no-auth 
 */
int cmd_get_default_auth(int socket, int none, char** empty);

static const console_cmd_t commands[] = {
    { "help", "prints existing commands (-h is an alias)", false, 0, NULL, cmd_print_help },
    { "users", "prints existing users", false, 0, NULL, cmd_list_users },
    { "stats", "prints server stats", false, 0, NULL, cmd_print_metrics },
    { "add", "registers a new user into database", true, 2, "UNAME PWD", cmd_add_user },
    { "del", "deletes a user from database", true, 1, "UNAME", cmd_delete_user },
    { "chpwd", "changes a user's password", true, 2, "UNAME NEWPWD", cmd_change_pwd },
    { "chrol", "switches a user's admin status", true, 2, "UNAME (admin|user)", cmd_change_role },
    { "audit", "prints a user's activity log", true, 1, "UNAME", cmd_audit_user },
    { "gauth", "gets current default authenticaton method", false, 0, NULL, cmd_get_default_auth },
    { "sauth", "sets default authentication method as no-auth or u/p", true, 1, "(no_auth|username_password)", cmd_set_default_auth }
};

#endif
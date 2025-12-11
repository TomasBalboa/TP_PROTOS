#include "client_cmd.h"
#include "client_utils.h"

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT "8080"

int main(int argc, char* argv[]){
    if(argc < 6){
        fprintf(stderr, "Usage: %s <host> <port> <username> <password> <command> [args]\n"
            "\tYou can use 'def' for host or port to use default values (localhost and 8080)\n\n"
            "Available commands:\n"
            "  HELP                                                        - Show all commands\n"
            "  LIST_USERS                                                  - List all users\n"
            "  STATS                                                       - Show server statistics\n"
            "  ADD_USER <username> <password>                  (admin only) - Register a new user\n"
            "  DELETE_USER <username>                          (admin only) - Delete a user\n"
            "  CHANGE_PASSWORD <username> <new_password>       (admin only) - Change user password\n"
            "  CHANGE_ROLE <username> <admin|user>             (admin only) - Change user role\n"
            "  AUDIT_USER <username>                           (admin only) - Show user activity log\n"
            "  GET_DEFAULT_AUTH                                            - Get current auth method\n"
            "  SET_DEFAULT_AUTH <no_auth|username_password>    (admin only) - Set default auth method\n"
            "\n"
            "Command aliases for convenience:\n"
            "  help, users, stats, add, del, chpwd, chrol, audit, gauth, sauth\n"
            "\n", argv[0]);
        return 1;
    }
    
    const char* host = strcmp(argv[1], "def") == 0 ? DEFAULT_HOST : argv[1]; //def --> default
    const char* port = strcmp(argv[2], "def") == 0 ? DEFAULT_PORT : argv[2]; //def --> default
    const char* username = argv[3];
    const char* password = argv[4];
    const char* command = argv[5];
    
    if(!strcmp(command,"-h") || !strcmp(command,"help")){
        cmd_print_help(0,0,NULL);
        return 0;
    }
    
    // Conectar al servidor
    int socket = client_open_socket(host, port);
    if(socket < 0){
        fprintf(stderr, "Error: Could not connect to %s:%s\n", host, port);
        return 1;
    }
    
    // Autenticar con las credenciales proporcionadas
    if(!client_authenticate(socket, username, password)){
        fprintf(stderr, "Error: Authentication failed for user '%s'\n", username);
        client_close_socket(socket);
        return 1;
    }
    
    for( int i = 0; i < CLIENT_CMD_SIZE; i++){
        if(!strcmp(command,commands[i].name)){
            if(argc - 6 != commands[i].argc){
                fprintf(stderr, "Wrong number of arguments\n\tProvided: %d\n\tExpected: %d\n", argc - 6, commands[i].argc);
                client_close_socket(socket);
                return 1;
            }
            int result = commands[i].command(socket, argc-6, argv + 6);
            client_close_socket(socket);
            return result ? 0 : 1;
        }
    }
    fprintf(stderr, "No reference of such command found\n\tTry 'help' or '-h' to find out which commands are available\n");
    client_close_socket(socket);
    return 1;
}

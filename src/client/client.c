#include "client_cmd.h"
#include "client_utils.h"

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT "8080"

int main(int argc, char* argv[]){
    if(argc < 4){
        fprintf(stderr, "Usage: %s <host> <port> <command> (args)\n"
            "\tTo know more about the commands, try 'help' or '-h'\n"
            "\tUse '$' as host or port if you wish to use the default values (localhost and 8080)\n", argv[0]);
        return 1;
    }
    
    const char* host = strcmp(argv[1], "$") == 0 ? DEFAULT_HOST : argv[1];
    const char* port = strcmp(argv[2], "$") == 0 ? DEFAULT_PORT : argv[2];
    
    if(!strcmp(argv[3],"-h") || !strcmp(argv[3],"help")){
        cmd_print_help(0,0,NULL);
        return 0;
    }
    
    // Conectar al servidor
    int socket = client_open_socket(host, port);
    if(socket < 0){
        fprintf(stderr, "Error: Could not connect to %s:%s\n", host, port);
        return 1;
    }
    
    // Autenticar
    if(!client_authenticate(socket, "admin", "0000")){
        fprintf(stderr, "Error: Authentication failed\n");
        client_close_socket(socket);
        return 1;
    }
    
    for( int i = 0; i < CLIENT_CMD_SIZE; i++){
        if(!strcmp(argv[3],commands[i].name)){
            if(argc - 4 != commands[i].argc){
                fprintf(stderr, "Wrong number of arguments\n\tProvided: %d\n\tExpected: %d\n", argc - 4, commands[i].argc);
                client_close_socket(socket);
                return 1;
            }
            int result = commands[i].command(socket, argc-4, argv + 4);
            client_close_socket(socket);
            return result ? 0 : 1;
        }
    }
    fprintf(stderr, "No reference of such command found\n\tTry 'help' or '-h' to find out which commands are available\n");
    client_close_socket(socket);
    return 1;
}

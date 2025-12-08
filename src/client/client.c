#include "client_cmd.h"
#include "client_utils.h"

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT "8080"

int main(int argc, char* argv[]){
    if(argc < 2){
        fprintf(stderr, "Usage: %s <host> <port> <command> (args)\n"
            "\tTo know more about the commands, try 'help' or '-h'\n"
            "\tUse '$' as host or port if you wish to use the default values (localhost and 8080)\n", argv[0]);
    }
    if(!strcmp(argv[1],"-h")){
        cmd_print_help(0,0,NULL);
    }
    for( int i = 0; i < CLIENT_CMD_SIZE; i++){
        if(!strcmp(argv[1],commands[i].name)){
            if(argc - 2 != commands[i].argc){
                fprintf(stderr, "Wrong number of arguments\n\tProvided: %d\n\tExpected: %d\n", argc - 2, commands[i].argc);
                return 0;
            }
            return commands[i].command(0, argc-2, argv + 2);
        }
    }
    fprintf(stderr, "No reference of such command found\n\tTry 'help' or '-h' to find out which commands are available\n");
    return 0;
}
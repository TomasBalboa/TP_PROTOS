#include "client_utils.h"

int main(int argc, char* argv[]){
    if(argc < 2){
        fprintf(stderr, "At least one command is expected\nTry '%s help' to know more\n", argv[0]);
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
    fprintf(stderr, "No reference of such command found\n");
    return 0;
}
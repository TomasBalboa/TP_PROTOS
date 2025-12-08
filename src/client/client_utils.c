#include "client_utils.h"

int cmd_print_help(int socket, int none, char** empty){
    (void) none; (void) empty; (void) socket;
    for(int i = 0; i < CLIENT_CMD_SIZE; i++){
        if(commands[i].args){
            printf("%s %s %s\n\t%s\n",
                commands[i].name, 
                commands[i].args, 
                commands[i].must_be_admin ? "(admin only)" : "",
                commands[i].summary
            );
        }else{
            printf("%s %s\n\t%s\n",
                commands[i].name,
                commands[i].must_be_admin ? "(admin only)" : "",
                commands[i].summary
            );
        }
    }
    return 1;
}

int cmd_list_users(int socket, int none, char** empty){
    (void) none; (void) empty; (void) socket;
    // placeholder, llama a management
    printf("+OK: printing users\n\tAndresCamalardo\n");
    return 1;
}

int cmd_print_metrics(int socket, int none, char** empty){
    (void) none; (void) empty; (void) socket;
    // placeholder, llama a management
    printf("+OK: printing stats\n\tat least 1 (one) user is reading stats\n");
    return 1;
}

int cmd_add_user(int socket, int two, char** args){
    (void) two; (void) socket;
    // placeholder, llama a management
    printf("+OK: adding user\n\tadded %s (password: %s)\n", args[0], args[1]);
    return 1;
}

int cmd_change_pwd(int socket, int two, char** args){
    (void) two; (void) socket;
    // placeholder, llama a management
    printf("+OK: changing password of %s\n\tnew password: %s\n", args[0], args[1]);
    return 1;
}

int cmd_delete_user(int socket, int one, char** user){
    (void) one; (void) socket;
    // placeholder, llama a management
    printf("+OK: deleting %s\n", user[0]);
    return 1;
}

int cmd_change_role(int socket, int two, char** args){
    (void) two; (void) socket;
    // placeholder, llama a management
    printf("+OK: changing role of %s\n\tnew role: %s\n", args[0], args[1]);
    return 1;
}

int cmd_audit_user(int socket, int one, char** user){
    (void) one; (void) socket;
    // placeholder, llama a management
    printf("+OK: auditing user\n\t-%s may or may not have done something\n", user[0]);
    return 1;
}

int cmd_set_default_auth(int socket, int one, char** method){
    (void) one; (void) socket;
    // placeholder, llama a management
    printf("+OK: setting default method as %s\n", method[0]);
    return 1;
}

int cmd_get_default_auth(int socket, int none, char** empty){    
    (void) none; (void) socket; (void) empty;
    // placeholder, llama a management
    printf("+OK: default method may be u/p or no-auth, idk\n");
    return 1;
}
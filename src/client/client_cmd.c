#include "client_cmd.h"
#include "client_utils.h"

int cmd_print_help(int socket, int none, char** empty){
    (void) none; (void) empty; (void) socket;
    printf("Usage: <exe> <host> <port> <command> (args)\nUse '$' as host or port if you wish to use the default values (localhost and 8080)\n\n");
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
    (void) none; (void) empty;
    return execute_simple_command(socket, 2, "users");
}

int cmd_print_metrics(int socket, int none, char** empty){
    (void) none; (void) empty;
    return execute_simple_command(socket, 3, "stats");
}

int cmd_add_user(int socket, int two, char** args){
    (void) two;
    const char* cmd_args[2] = {args[0], args[1]};
    return execute_command_with_args(socket, 0, cmd_args, 2, "user added");
}

int cmd_change_pwd(int socket, int two, char** args){
    (void) two; (void) socket; (void) args;
    
    printf("-ERR: command not implemented on server\n");
    return 0;
}

int cmd_delete_user(int socket, int one, char** user){
    (void) one;
    const char* cmd_args[1] = {user[0]};
    return execute_command_with_args(socket, 1, cmd_args, 1, "user deleted");
}

int cmd_change_role(int socket, int two, char** args){
    (void) two;
    const char* cmd_args[2] = {args[0], args[1]};
    return execute_command_with_args(socket, 4, cmd_args, 2, "role changed");
}

int cmd_audit_user(int socket, int one, char** user){
    (void) one;
    const char* cmd_args[1] = {user[0]};
    
    /* Construir payload: username */
    char payload[256];
    int payload_len = snprintf(payload, sizeof(payload), "%s", user[0]);
    
    if(!send_mgmt_command(socket, 7, payload, payload_len)){
        printf("-ERR: failed to send command\n");
        return 0;
    }
    
    char response[4096];
    size_t response_len;
    uint8_t status = recv_mgmt_response(socket, response, &response_len);
    
    if(status != 0){
        printf("-ERR: %s\n", response_len > 0 ? response : "command failed");
        return 0;
    }
    
    printf("+OK: activity log for '%s'\n%s", cmd_args[0], response);
    return 1;
}

int cmd_set_default_auth(int socket, int one, char** method){
    (void) one;
    const char* cmd_args[1] = {method[0]};
    return execute_command_with_args(socket, 5, cmd_args, 1, 
                                     "default auth method set");
}

int cmd_get_default_auth(int socket, int none, char** empty){    
    (void) none; (void) empty;
    return execute_simple_command(socket, 6, "default auth method");
}

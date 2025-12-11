#include "client_utils.h"
#include <unistd.h>

#define MGMT_VERSION 1

// Códigos de comando
typedef enum {
    MGMT_ADD_USER    = 0,
    MGMT_DELETE_USER = 1,
    MGMT_LIST_USERS  = 2,
    MGMT_STATS       = 3,
    MGMT_CHANGE_ROLE = 4,
    MGMT_SET_DEFAULT_AUTH_METHOD = 5,
    MGMT_GET_DEFAULT_AUTH_METHOD = 6,
    MGMT_USER_ACTIVITY = 7
} mgmt_command_code;

int client_open_socket(const char* host, const char* service){
    struct addrinfo address;
    memset(&address, 0, sizeof(address));
    address.ai_family = AF_UNSPEC; // ipv4 o ipv6
    address.ai_socktype = SOCK_STREAM;
    address.ai_protocol = IPPROTO_TCP;

    struct addrinfo* servers;
    if(getaddrinfo(host, service, &address, &servers)) return -1;

    int ans = -1;
    for(struct addrinfo* aux = servers; aux && ans == -1; aux = aux->ai_next){
        ans = socket(aux->ai_family, aux->ai_socktype, aux->ai_protocol);
        if(ans > -1){
            errno = 0;
            if(connect(ans,aux->ai_addr,aux->ai_addrlen) != 0){
                close(ans);
                ans = -1;
            }
        }
    }

    freeaddrinfo(servers);
    return ans;
}

void client_close_socket(int fd){
    if(fd >= 0)
        close(fd);
}

bool client_authenticate(int fd, const char* uname, const char* pwd){
    int ulen = strlen(uname);
    int plen = strlen(pwd);
    if(ulen > 255 || plen > 255) return false;

    uint8_t request[MAX_AUP_REQUEST_SIZE] = {AUP_VERSION, ulen};
    int offset = 2;
    memcpy(request+offset,uname,ulen);
    offset+=ulen;
    request[offset] = plen;
    offset++;
    memcpy(request+offset,pwd,plen);
    offset+=plen;

    if(send(fd,request,offset,0) < 0){
        printf("Error sending authentication credentials\n");
        return false;
    }

    uint8_t ver, status;

    if((read(fd,&ver,1) <= 0) || (read(fd,&status,1) <= 0)){
        printf("Error recieving authentication credentials\n");
        return false;
    }

    if(status){
        printf("Username and/or password may not be correct\n");
        return false;
    }

    return true;
}

bool send_mgmt_command(int fd, uint8_t command, const char* payload, uint8_t payload_len){
    uint8_t request[3 + 255]; // VERSION + COMMAND + LENGTH + max payload
    
    request[0] = MGMT_VERSION;
    request[1] = command;
    request[2] = payload_len;
    
    size_t total = 3;
    if(payload_len > 0 && payload != NULL){
        memcpy(request + 3, payload, payload_len);
        total += payload_len;
    }
    
    ssize_t sent = send(fd, request, total, 0);
    if(sent != (ssize_t)total){
        return false;
    }
    
    return true;
}

uint8_t recv_mgmt_response(int fd, char* response, size_t* response_len){
    uint8_t version, status;
    
    // Leer VERSION
    if(read(fd, &version, 1) <= 0){
        return 255; // Error de lectura
    }
    
    if(version != MGMT_VERSION){
        return 254; // Versión incorrecta
    }
    
    // Leer STATUS
    if(read(fd, &status, 1) <= 0){
        return 255; // Error de lectura
    }
    
    // Leer mensaje (resto de datos disponibles)
    ssize_t n = read(fd, response, 255);
    if(n < 0){
        *response_len = 0;
        return status;
    }
    
    response[n] = '\0';
    *response_len = n;
    
    return status;
}

/* Funciones auxiliares */

int execute_simple_command(int fd, uint8_t cmd_code, const char* success_msg){
    if(!send_mgmt_command(fd, cmd_code, NULL, 0)){
        printf("-ERR: failed to send command\n");
        return 0;
    }
    
    char response[256];
    size_t response_len;
    uint8_t status = recv_mgmt_response(fd, response, &response_len);
    
    if(status != 0){
        printf("-ERR: command failed (status=%d)\n", status);
        return 0;
    }
    
    printf("+OK: %s\n%s", success_msg, response);
    return 1;
}

int execute_command_with_args(int fd, uint8_t cmd_code, const char** args, 
                               int arg_count, const char* success_msg){
    char payload[256];
    int pos = 0;
    
    // Construir payload separado por ':'
    for(int i = 0; i < arg_count; i++){
        int written = snprintf(payload + pos, sizeof(payload) - pos, 
                              "%s%s", (i > 0 ? ":" : ""), args[i]);
        if(written < 0 || pos + written >= (int)sizeof(payload)){
            printf("-ERR: arguments too long\n");
            return 0;
        }
        pos += written;
    }
    
    if(!send_mgmt_command(fd, cmd_code, payload, pos)){
        printf("-ERR: failed to send command\n");
        return 0;
    }
    
    char response[256];
    size_t response_len;
    uint8_t status = recv_mgmt_response(fd, response, &response_len);
    
    if(status != 0){
        printf("-ERR: %s\n", response_len > 0 ? response : "command failed");
        return 0;
    }
    
    printf("+OK: %s\n", success_msg);
    return 1;
}

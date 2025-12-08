#include "client_utils.h"

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

bool client_authenticate(int fd, char* uname, char* pwd){
    int ulen = strlen(uname);
    int plen = strlen(pwd);
    if(ulen > 255 || plen > 255) return false;

    uint8_t request[MAX_AUP_REQUEST_SIZE] = {AUP_VERSION, ulen};
    int offset = 2;
    memcpy(request+offset,uname,ulen);
    offset+=ulen;
    request[offset] = plen;
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
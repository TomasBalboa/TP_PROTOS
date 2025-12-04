#include "metrics.h"

static metrics_t stats;

void metricsInit(void){
    memset(&stats, 0, sizeof(stats));
    stats.uptime = time(NULL);
}

void metrics_login(void){
    stats.current_connections++;
    stats.total_connections++;
    stats.max_connections = ( stats.current_connections > stats.max_connections ) ? stats.current_connections : stats.max_connections;
}

void metrics_logout(void){
    stats.current_connections --;
}

void metrics_update(size_t bytes_sent, size_t bytes_recieved){
    stats.bytes_sent += bytes_sent;
    stats.bytes_recieved += bytes_recieved;
}

void metrics_getter(metrics_t* metrics){
    if(metrics){
        memcpy(metrics, &stats, sizeof(metrics_t));
    }
}

void metrics_query_dns(void){
    stats.dns_queries++;
}

time_t metrics_get_uptime(void){
    return time(NULL) - stats.uptime;
}

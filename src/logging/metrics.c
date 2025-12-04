#include "metrics.h"

static metrics_t stats;

void metricsInit(){
    memset(&stats, 0, sizeof(stats));
    stats.uptime = time(NULL);
}

void metrics_login(){
    stats.current_connections++;
    stats.total_connections++;
    stats.max_connections = ( stats.current_connections > stats.max_connections ) ? stats.current_connections : stats.max_connections;
}

void metrics_logout(){
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

void metrics_query_dns(){
    stats.dns_queries++;
}

time_t metrics_get_uptime(){
    return time(NULL) - stats.uptime;
}
#include "graph_window.h"
#include <string.h>
#include <math.h>

static GWTracker trackers[GW_MAX_IPS]; 
static double window_size = 60.0; // dimensiunea ferestrei in secunde

void graph_window_init(double window_seconds) {
    window_size = window_seconds;
    memset(trackers, 0, sizeof(trackers)); // initializez toti trackerii cu 0 (active=0, n_dst_ips=0, n_dst_ports=0)
}

//gasire sau creare tracker pentru src_ip
static GWTracker *find_or_create_tracker(uint32_t src_ip) {
    int first_free = -1;
    for (int i = 0; i < GW_MAX_IPS; i++) {
        if (trackers[i].active && trackers[i].src_ip == src_ip) {
            return &trackers[i]; // am gasit trackerul pentru src_ip, il returnez
        }
        if (!trackers[i].active && first_free == -1) {
            first_free = i; // retinem primul slot liber pentru a putea crea un nou tracker
        }
    }
        if(first_free == -1) return NULL; //nu mai e loc

        memset(&trackers[first_free], 0, sizeof(GWTracker)); // initializez noul tracker cu 0
        trackers[first_free].src_ip = src_ip; // setez src_ip
        trackers[first_free].active = 1; // marchez slotul ca ocupat
        return &trackers[first_free]; // returnez noul tracker creat
} //*cautam first_free in acelasi loop pt O(n) in loc de O(2n)


//evict intrarile mai vechi de cutokk
static void evict_old(GWEntry *entries, int *count, double cutoff) {
    int write = 0;
    for(int read = 0; read < *count; read++) {
        if(entries[read].timestamp >= cutoff) {
            entries[write] = entries[read]; // pastrez doar intrarile mai noi decat cutoff
            write++;
        }
    }
    *count = write; // actualizez numarul de intrari dupa evict
} //*tehnica two-pointer compaction - read=parcurge toate intrarile, write-copiazaa doar intrarile valide, count e actualizat cu numarul de intrari ramanse 

//update
void graph_window_update(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port, double timestamp) {
    GWTracker *tracker = find_or_create_tracker(src_ip);
    if (!tracker) {
        return;//nu mai e loc
    }

    double cutoff = timestamp - window_size; // calculam cutoff pentru a elimina intrarile mai vechi decat fereastra

    //evict intrarile vechi din dst_ips si dst_ports
    evict_old(tracker->dst_ips, &tracker->n_dst_ips, cutoff);
    evict_old(tracker->dst_ports, &tracker->n_dst_ports, cutoff);

    if(tracker->n_dst_ips < GW_MAX_ENTRIES) {
        tracker->dst_ips[tracker->n_dst_ips].timestamp = timestamp; // adaugam noua intrare cu timestamp curent
        tracker->dst_ips[tracker->n_dst_ips].value = dst_ip;
        tracker->n_dst_ips++;
    }

    if(tracker->n_dst_ports < GW_MAX_ENTRIES) {
        tracker->dst_ports[tracker->n_dst_ports].timestamp = timestamp; // adaugam noua intrare cu timestamp curent
        tracker->dst_ports[tracker->n_dst_ports].value = (uint32_t)dst_port;
        tracker->n_dst_ports++;
    }
}

//extract - feature pt un src_ip la un moment dat
GraphFeatures graph_window_extract(uint32_t src_ip, double current_time) {
    GraphFeatures result = {0, 0, 0.0};

    GWTracker *tracker = find_or_create_tracker(src_ip);
    if (!tracker || tracker->n_dst_ips == 0) {
        return result; 
    }
    double cutoff = current_time - window_size; // calculam cutoff pentru a elimina intrarile mai vechi decat fereastra
    evict_old(tracker->dst_ips, &tracker->n_dst_ips, cutoff);
    evict_old(tracker->dst_ports, &tracker->n_dst_ports, cutoff);

    //numaram de cate ori aparre fiecare ip dectinatie
    uint32_t ip_vals[GW_MAX_ENTRIES];
    int ip_cnt[GW_MAX_ENTRIES];
    int n_unique = 0;

    for(int i = 0; i < tracker->n_dst_ips; i++) {
        uint32_t ip = tracker->dst_ips[i].value;
        int found = 0;
        for(int j = 0; j < n_unique; j++) {
            if(ip_vals[j] == ip) {
                ip_cnt[j]++;
                found = 1;
                break;
            }
        }
        if(!found && n_unique < GW_MAX_ENTRIES) {
            ip_vals[n_unique] = ip;
            ip_cnt[n_unique] = 1;
            n_unique++;
        }
    }
    result.unique_dst_ips = (uint32_t)n_unique;

    //enotropia
    double entropy = 0.0;
    double total = (double)tracker->n_dst_ips;

    for(int i = 0; i < n_unique; i++) {
        double p = (double)ip_cnt[i] / total; // probabilitatea de a contacta destinatia i
        entropy -= p * log2(p);
    }
    result.dst_entropy = entropy;

    //numaram porturile unice
    uint32_t port_vals[GW_MAX_ENTRIES];
    int n_unique_ports = 0;

    for(int i = 0; i < tracker->n_dst_ports; i++) {
        uint32_t port = tracker->dst_ports[i].value;
        int found = 0;
        for(int j = 0; j < n_unique_ports; j++) {
            if(port_vals[j] == port) {
                found = 1;
                break;
            }
        }
        if(!found && n_unique_ports < GW_MAX_ENTRIES) {
            port_vals[n_unique_ports] = port;
            n_unique_ports++;
        }
    }
    result.unique_dst_ports = (uint32_t)n_unique_ports;

    return result;
}

//connecton degree - cate fluxuri active are src_ip la momentul actual
//calculata in flow_table.c folosind functia graph_window_count_active_flows, care numara cate fluxuri active are src_ip in flow_table la momentul actual, si se completeaza campul connection_degree din FlowStats la finalizarea fluxului
int graph_window_count_active_flows(uint32_t src_ip) {
    (void)src_ip;
    return 0;
}
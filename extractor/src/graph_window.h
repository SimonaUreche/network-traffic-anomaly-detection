#pragma once
#include <stdint.h>
#include "packet_parser.h"

#define GW_MAX_IPS 64 //6 cotainers = 6 IP-uri + IP de atacuri => 64 suficient
#define GW_MAX_ENTRIES 1024 //cate conexiuni/intrari avem pe IP? ~ un senozr Iot ~6 fluxuri/minut=~360 pachete pe minut in fereastra de 60s => 1024 suficient

typedef struct { //intrare in fereastra, ca sa stim ce IP-uri sunt active in fereastra curenta si ce timestamp are fiecare intrare pentru a putea elimina intrarile vechi
    double timestamp;
    uint32_t value;
} GWEntry;

//tot ce stim despre src_ip in ferestra curenta
typedef struct {
    uint32_t src_ip;
    int active; //1=slot folosit

    GWEntry dst_ips[GW_MAX_ENTRIES]; //lista de IP-uri destinatie unice cu care a comunicat src_ip in fereastra curenta
    int n_dst_ips; 

    GWEntry dst_ports[GW_MAX_ENTRIES]; //lista de porturi destinatie unice cu care a comunicat src_ip in fereastra curenta
    int n_dst_ports;

}GWTracker;

//rezultatul pt un src_ip la un moment dat
typedef struct {
    uint32_t unique_dst_ips; //cate ip-uri diferite a contactat src in ultimele 60s
    uint32_t unique_dst_ports; //cate porturi diferite a contactat src in ultimele 60s
    double dst_entropy; //cat de uniform e distribuit traficul catre destinatii
    // Formula: -Σ p(dst_i) * log2(p(dst_i))
    //iot_sensor normal: 100% trafic → gateway. ===> entropy = -(1.0 * log2(1.0)) = 0.0  (zero entropie, o singură destinație)
    //port scan:1% trafic → fiecare din 100 IP-uri ===> entropy = -(100 * 0.01 * log2(0.01)) ≈ 6.6  (entropie mare, distribuit uniform)
} GraphFeatures;


//FUNCTII
void graph_window_init(double window_seconds);  
void graph_window_update(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port, double timestamp);
GraphFeatures graph_window_extract(uint32_t src_ip, double current_time);
int graph_window_count_active_flows(uint32_t src_ip);

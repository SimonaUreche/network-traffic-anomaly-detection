#pragma once
#include <stdint.h>
#include "packet_parser.h"

typedef struct {
    uint32_t ip_a;       // IP-ul mai mic (numeric)
    uint32_t ip_b;       // IP-ul mai mare
    uint16_t port_a;     // portul asociat cu ip_a
    uint16_t port_b;     // portul asociat cu ip_b
    uint8_t  protocol;
} FlowKey;

typedef struct {
    FlowKey key;
    char device_type[32];

    // Cine a initiat conexiunea
    uint32_t initiator_ip;
    uint16_t initiator_port;
    uint32_t responder_ip;
    uint16_t responder_port;

    // Timing global
    double first_seen;
    double last_seen;

    // ══════ FORWARD (initiator → responder) ══════
    uint64_t fwd_total_packets;
    uint64_t fwd_total_bytes;
    uint32_t fwd_min_pkt_size;
    uint32_t fwd_max_pkt_size;
    double   fwd_sum_pkt_size;
    double   fwd_sum_sq_pkt_size;

    double   fwd_sum_iat;
    double   fwd_sum_sq_iat;
    double   fwd_last_pkt_time;
    uint32_t fwd_iat_count;

    uint32_t fwd_syn_count;
    uint32_t fwd_ack_count;
    uint32_t fwd_fin_count;
    uint32_t fwd_rst_count;
    uint32_t fwd_psh_count;

    // ══════ REVERSE (responder → initiator) ══════
    uint64_t rev_total_packets;
    uint64_t rev_total_bytes;
    uint32_t rev_min_pkt_size;
    uint32_t rev_max_pkt_size;
    double   rev_sum_pkt_size;
    double   rev_sum_sq_pkt_size;

    double   rev_sum_iat;
    double   rev_sum_sq_iat;
    double   rev_last_pkt_time;
    uint32_t rev_iat_count;

    uint32_t rev_syn_count;
    uint32_t rev_ack_count;
    uint32_t rev_fin_count;
    uint32_t rev_rst_count;
    uint32_t rev_psh_count;

    // ══════ GRAPH FEATURES (calculate la finalizare) ══════
    uint32_t unique_dst_ips;
    uint32_t unique_dst_ports;
    uint32_t connection_degree;
    double   dst_entropy;

    // ══════ DERIVED FEATURES ══════
    uint8_t is_standard_port;
    uint8_t is_internal_only;
    uint8_t is_night_traffic;
    uint8_t is_known_pair;
} FlowStats;

void flow_table_init(void);

void flow_table_process_packet(const ParsedPacket *pkt,
                                const char *device_type,
                                FlowStats         *completed,
                                int               *n_completed);

void flow_table_collect_expired(double    current_time,
                                 double    timeout_seconds,
                                 FlowStats *completed,
                                 int       *n_completed);

void flow_table_flush_all(FlowStats *completed, int *n_completed);

/* Calcule per directie */
double flow_fwd_avg_pkt_size(const FlowStats *f);
double flow_fwd_std_pkt_size(const FlowStats *f);
double flow_fwd_avg_iat(const FlowStats *f);
double flow_fwd_std_iat(const FlowStats *f);
double flow_rev_avg_pkt_size(const FlowStats *f);
double flow_rev_std_pkt_size(const FlowStats *f);
double flow_rev_avg_iat(const FlowStats *f);
double flow_rev_std_iat(const FlowStats *f);
double flow_duration(const FlowStats *f);

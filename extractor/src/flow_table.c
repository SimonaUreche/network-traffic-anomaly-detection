#include "flow_table.h"
#include "packet_parser.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "graph_window.h"
#include <time.h>

#define MAX_FLOWS 4096

static int is_standard_port(uint16_t port) {
    return (port == 22 || port == 53 || port == 80 ||
            port == 443 || port == 1883);
}

static int is_internal_ip(uint32_t ip) {
    unsigned char *bytes = (unsigned char *)&ip;
    return (bytes[0] == 172 && bytes[1] == 20 && bytes[2] == 0);
}

static int is_night_hour(double timestamp) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    return (tm_info->tm_hour >= 0 && tm_info->tm_hour < 6);
}

typedef struct {
    uint8_t ip_a[4];
    uint8_t ip_b[4];
    uint16_t port;
} KnownPair;

static const KnownPair KNOWN_PAIRS[] = {
    {{172,20,0,2}, {172,20,0,5}, 22},
    {{172,20,0,2}, {172,20,0,3}, 80},
    {{172,20,0,2}, {172,20,0,53}, 53},
    {{172,20,0,2}, {172,20,0,4}, 1883},
    {{172,20,0,4}, {172,20,0,2}, 1883},
    {{172,20,0,6}, {172,20,0,2}, 1883},
    {{172,20,0,6}, {172,20,0,3}, 80},
    {{172,20,0,7}, {172,20,0,2}, 1883},
};
#define N_KNOWN_PAIRS (sizeof(KNOWN_PAIRS) / sizeof(KNOWN_PAIRS[0]))

static int ip_bytes_match(const uint8_t ref[4], uint32_t ip) {
    unsigned char *b = (unsigned char *)&ip;
    return (b[0] == ref[0] && b[1] == ref[1] &&
            b[2] == ref[2] && b[3] == ref[3]);
}

static int is_known_pair(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port) {
    for (int i = 0; i < (int)N_KNOWN_PAIRS; i++) {
        if (ip_bytes_match(KNOWN_PAIRS[i].ip_a, src_ip) &&
            ip_bytes_match(KNOWN_PAIRS[i].ip_b, dst_ip) &&
            dst_port == KNOWN_PAIRS[i].port) {
            return 1;
        }
        if (ip_bytes_match(KNOWN_PAIRS[i].ip_b, src_ip) &&
            ip_bytes_match(KNOWN_PAIRS[i].ip_a, dst_ip) &&
            dst_port == KNOWN_PAIRS[i].port) {
            return 1;
        }
    }
    return 0;
}

static FlowKey make_bidir_key(uint32_t src_ip, uint32_t dst_ip,
                               uint16_t src_port, uint16_t dst_port,
                               uint8_t protocol) {
    FlowKey key;
    key.protocol = protocol;

    uint32_t src_h = ntohl(src_ip);
    uint32_t dst_h = ntohl(dst_ip);

    if (src_h < dst_h || (src_h == dst_h && src_port <= dst_port)) {
        key.ip_a = src_ip;
        key.ip_b = dst_ip;
        key.port_a = src_port;
        key.port_b = dst_port;
    } else {
        key.ip_a = dst_ip;
        key.ip_b = src_ip;
        key.port_a = dst_port;
        key.port_b = src_port;
    }
    return key;
}

typedef struct {
    FlowStats flow;
    int occupied;
} FlowSlot;

static FlowSlot flow_table[MAX_FLOWS];
static int table_init = 0;

static uint32_t hash_flow_key(const FlowKey *key) {
    uint32_t hash = 2166136261u;
    hash = (hash ^ key->ip_a)    * 16777619u;
    hash = (hash ^ key->ip_b)    * 16777619u;
    hash = (hash ^ key->port_a)  * 16777619u;
    hash = (hash ^ key->port_b)  * 16777619u;
    hash = (hash ^ key->protocol)* 16777619u;
    return hash % MAX_FLOWS;
}

static int flow_keys_equal(const FlowKey *a, const FlowKey *b) {
    return a->ip_a == b->ip_a &&
           a->ip_b == b->ip_b &&
           a->port_a == b->port_a &&
           a->port_b == b->port_b &&
           a->protocol == b->protocol;
}

static FlowStats *find_or_create(const FlowKey *key, const char *device_type, int create) {
    uint32_t index = hash_flow_key(key);

    for (int i = 0; i < MAX_FLOWS; i++) {
        uint32_t slot = (index + i) % MAX_FLOWS;

        if (!flow_table[slot].occupied) {
            if (!create) return NULL;

            memset(&flow_table[slot].flow, 0, sizeof(FlowStats));
            flow_table[slot].flow.key = *key;
            strncpy(flow_table[slot].flow.device_type, device_type,
                    sizeof(flow_table[slot].flow.device_type) - 1);
            flow_table[slot].flow.fwd_min_pkt_size = UINT32_MAX;
            flow_table[slot].flow.rev_min_pkt_size = UINT32_MAX;
            flow_table[slot].occupied = 1;
            return &flow_table[slot].flow;
        }
        if (flow_keys_equal(&flow_table[slot].flow.key, key)) {
            return &flow_table[slot].flow;
        }
    }
    return NULL;
}

static void init_flow_direction(FlowStats *flow, const ParsedPacket *pkt) {
    if (pkt->protocol == 6 && (pkt->tcp_flags & 0x02) && !(pkt->tcp_flags & 0x10)) {
        // SYN fara ACK -> initiatorul e sursa
        flow->initiator_ip   = pkt->src_ip;
        flow->initiator_port = pkt->src_port;
        flow->responder_ip   = pkt->dst_ip;
        flow->responder_port = pkt->dst_port;
    } else {
        flow->initiator_ip   = pkt->src_ip;
        flow->initiator_port = pkt->src_port;
        flow->responder_ip   = pkt->dst_ip;
        flow->responder_port = pkt->dst_port;
    }
}

static void add_packet_to_flow(FlowStats *flow, const ParsedPacket *pkt) {
    double size = (double)pkt->packet_length;
    int is_new_flow = (flow->fwd_total_packets == 0 && flow->rev_total_packets == 0);

    if (is_new_flow) {
        flow->first_seen = pkt->timestamp;
        init_flow_direction(flow, pkt);
    }
    flow->last_seen = pkt->timestamp;

    int is_forward = (pkt->src_ip == flow->initiator_ip &&
                      pkt->src_port == flow->initiator_port);

    if (is_forward) {
        if (flow->fwd_total_packets > 0) {
            double iat = pkt->timestamp - flow->fwd_last_pkt_time;
            flow->fwd_sum_iat    += iat;
            flow->fwd_sum_sq_iat += iat * iat;
            flow->fwd_iat_count++;
        }
        flow->fwd_last_pkt_time = pkt->timestamp;

        flow->fwd_total_packets++;
        flow->fwd_total_bytes += pkt->packet_length;
        flow->fwd_sum_pkt_size    += size;
        flow->fwd_sum_sq_pkt_size += size * size;

        if (pkt->packet_length < flow->fwd_min_pkt_size)
            flow->fwd_min_pkt_size = pkt->packet_length;
        if (pkt->packet_length > flow->fwd_max_pkt_size)
            flow->fwd_max_pkt_size = pkt->packet_length;

        if (pkt->tcp_flags & 0x02) flow->fwd_syn_count++;
        if (pkt->tcp_flags & 0x10) flow->fwd_ack_count++;
        if (pkt->tcp_flags & 0x01) flow->fwd_fin_count++;
        if (pkt->tcp_flags & 0x04) flow->fwd_rst_count++;
        if (pkt->tcp_flags & 0x08) flow->fwd_psh_count++;
    } else {
        if (flow->rev_total_packets > 0) {
            double iat = pkt->timestamp - flow->rev_last_pkt_time;
            flow->rev_sum_iat    += iat;
            flow->rev_sum_sq_iat += iat * iat;
            flow->rev_iat_count++;
        }
        flow->rev_last_pkt_time = pkt->timestamp;

        flow->rev_total_packets++;
        flow->rev_total_bytes += pkt->packet_length;
        flow->rev_sum_pkt_size    += size;
        flow->rev_sum_sq_pkt_size += size * size;

        if (pkt->packet_length < flow->rev_min_pkt_size)
            flow->rev_min_pkt_size = pkt->packet_length;
        if (pkt->packet_length > flow->rev_max_pkt_size)
            flow->rev_max_pkt_size = pkt->packet_length;

        if (pkt->tcp_flags & 0x02) flow->rev_syn_count++;
        if (pkt->tcp_flags & 0x10) flow->rev_ack_count++;
        if (pkt->tcp_flags & 0x01) flow->rev_fin_count++;
        if (pkt->tcp_flags & 0x04) flow->rev_rst_count++;
        if (pkt->tcp_flags & 0x08) flow->rev_psh_count++;
    }
}

static void finalize_flow(FlowStats *flow, double current_time) {
    GraphFeatures gf = graph_window_extract(flow->initiator_ip, current_time);
    flow->unique_dst_ips   = gf.unique_dst_ips;
    flow->unique_dst_ports = gf.unique_dst_ports;
    flow->dst_entropy      = gf.dst_entropy;

    uint32_t degree = 0;
    for (uint32_t j = 0; j < MAX_FLOWS; j++) {
        if (flow_table[j].occupied &&
            flow_table[j].flow.initiator_ip == flow->initiator_ip) {
            degree++;
        }
    }
    flow->connection_degree = degree;
    flow->is_standard_port  = is_standard_port(flow->responder_port);
    flow->is_internal_only  = is_internal_ip(flow->initiator_ip) && is_internal_ip(flow->responder_ip);
    flow->is_night_traffic  = is_night_hour(flow->first_seen);
    flow->is_known_pair     = is_known_pair(flow->initiator_ip, flow->responder_ip, flow->responder_port);
}

///////////////FUNCTII PUBLICE///////////////
void flow_table_init(void) {
    memset(flow_table, 0, sizeof(flow_table));
    table_init = 1;
}

void flow_table_process_packet(const ParsedPacket *pkt, const char *device_type,
                                FlowStats *completed, int *n_completed) {
    *n_completed = 0;

    FlowKey key = make_bidir_key(pkt->src_ip, pkt->dst_ip,
                                  pkt->src_port, pkt->dst_port,
                                  pkt->protocol);

    // graph_window se apeleaza cu initiator/responder — determinat dupa ce gasim/cream flow-ul
    FlowStats *flow = find_or_create(&key, device_type, 1);
    if (!flow) {
        fprintf(stderr, "Warning: flow table full\n");
        return;
    }

    int is_new = (flow->fwd_total_packets == 0 && flow->rev_total_packets == 0);
    add_packet_to_flow(flow, pkt);

    // graph_window update cu initiator_ip (setat de add_packet_to_flow la primul pachet)
    graph_window_update(flow->initiator_ip, flow->responder_ip, flow->responder_port, pkt->timestamp);

    // TCP FIN sau RST -> flux terminat
    if (pkt->protocol == 6 && (pkt->tcp_flags & 0x01 || pkt->tcp_flags & 0x04)) {
        finalize_flow(flow, pkt->timestamp);
        completed[*n_completed] = *flow;
        (*n_completed)++;

        uint32_t index = hash_flow_key(&key);
        for (uint32_t i = 0; i < MAX_FLOWS; i++) {
            uint32_t slot = (index + i) % MAX_FLOWS;
            if (flow_table[slot].occupied && flow_keys_equal(&flow_table[slot].flow.key, &key)) {
                flow_table[slot].occupied = 0;
                break;
            }
        }
    }

    (void)is_new;
}

void flow_table_collect_expired(double current_time, double timeout_seconds,
                                  FlowStats *completed, int *n_completed) {
    *n_completed = 0;

    for (int i = 0; i < MAX_FLOWS; i++) {
        if (!flow_table[i].occupied) continue;

        double idle = current_time - flow_table[i].flow.last_seen;
        if (idle >= timeout_seconds) {
            finalize_flow(&flow_table[i].flow, current_time);
            completed[*n_completed] = flow_table[i].flow;
            (*n_completed)++;
            flow_table[i].occupied = 0;
        }
    }
}

void flow_table_flush_all(FlowStats *completed, int *n_completed) {
    *n_completed = 0;

    for (int i = 0; i < MAX_FLOWS; i++) {
        if (!flow_table[i].occupied) continue;

        finalize_flow(&flow_table[i].flow, flow_table[i].flow.last_seen);
        completed[*n_completed] = flow_table[i].flow;
        (*n_completed)++;
        flow_table[i].occupied = 0;
    }
}

///////Functii calcul////
double flow_fwd_avg_pkt_size(const FlowStats *f) {
    if (f->fwd_total_packets == 0) return 0.0;
    return f->fwd_sum_pkt_size / (double)f->fwd_total_packets;
}

double flow_fwd_std_pkt_size(const FlowStats *f) {
    if (f->fwd_total_packets < 2) return 0.0;
    double avg = flow_fwd_avg_pkt_size(f);
    double variance = (f->fwd_sum_sq_pkt_size / (double)f->fwd_total_packets) - (avg * avg);
    return variance > 0.0 ? sqrt(variance) : 0.0;
}

double flow_fwd_avg_iat(const FlowStats *f) {
    if (f->fwd_iat_count == 0) return 0.0;
    return f->fwd_sum_iat / (double)f->fwd_iat_count;
}

double flow_fwd_std_iat(const FlowStats *f) {
    if (f->fwd_iat_count < 2) return 0.0;
    double avg = flow_fwd_avg_iat(f);
    double variance = (f->fwd_sum_sq_iat / (double)f->fwd_iat_count) - (avg * avg);
    return variance > 0.0 ? sqrt(variance) : 0.0;
}

double flow_rev_avg_pkt_size(const FlowStats *f) {
    if (f->rev_total_packets == 0) return 0.0;
    return f->rev_sum_pkt_size / (double)f->rev_total_packets;
}

double flow_rev_std_pkt_size(const FlowStats *f) {
    if (f->rev_total_packets < 2) return 0.0;
    double avg = flow_rev_avg_pkt_size(f);
    double variance = (f->rev_sum_sq_pkt_size / (double)f->rev_total_packets) - (avg * avg);
    return variance > 0.0 ? sqrt(variance) : 0.0;
}

double flow_rev_avg_iat(const FlowStats *f) {
    if (f->rev_iat_count == 0) return 0.0;
    return f->rev_sum_iat / (double)f->rev_iat_count;
}

double flow_rev_std_iat(const FlowStats *f) {
    if (f->rev_iat_count < 2) return 0.0;
    double avg = flow_rev_avg_iat(f);
    double variance = (f->rev_sum_sq_iat / (double)f->rev_iat_count) - (avg * avg);
    return variance > 0.0 ? sqrt(variance) : 0.0;
}

double flow_duration(const FlowStats *f) {
    return f->last_seen - f->first_seen;
}

#include "csv_writer.h"
#include "flow_table.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <math.h>

static void ip_to_str(uint32_t ip, char *buf, size_t buflen) {
    struct in_addr addr;
    addr.s_addr = ip;
    snprintf(buf, buflen, "%s", inet_ntoa(addr));
}

FILE *csv_writer_open(const char *filename)
{
    FILE *f = fopen(filename, "w");
    if (!f) return NULL;

    fprintf(f,
        "src_ip,dst_ip,src_port,dst_port,protocol,"
        "fwd_total_packets,fwd_total_bytes,"
        "fwd_avg_pkt_size,fwd_std_pkt_size,fwd_min_pkt_size,fwd_max_pkt_size,"
        "fwd_avg_iat,fwd_std_iat,"
        "fwd_syn_count,fwd_ack_count,fwd_fin_count,fwd_rst_count,fwd_psh_count,"
        "rev_total_packets,rev_total_bytes,"
        "rev_avg_pkt_size,rev_std_pkt_size,rev_min_pkt_size,rev_max_pkt_size,"
        "rev_avg_iat,rev_std_iat,"
        "rev_syn_count,rev_ack_count,rev_fin_count,rev_rst_count,rev_psh_count,"
        "flow_duration,"
        "total_packets,total_bytes,"
        "fwd_rev_packet_ratio,fwd_rev_byte_ratio,"
        "unique_dst_ips,unique_dst_ports,connection_degree,dst_entropy,"
        "is_standard_port,is_internal_only,is_night_traffic,is_known_pair,"
        "device_type,label\n"
    );

    return f;
}

void csv_writer_write(FILE *file, const FlowStats *flow)
{
    char src_buf[INET_ADDRSTRLEN];
    char dst_buf[INET_ADDRSTRLEN];

    // src_ip/dst_ip = initiator/responder (nu ip_a/ip_b din cheie)
    ip_to_str(flow->initiator_ip, src_buf, sizeof(src_buf));
    ip_to_str(flow->responder_ip, dst_buf, sizeof(dst_buf));

    double fwd_avg_pkt  = flow_fwd_avg_pkt_size(flow);
    double fwd_std_pkt  = flow_fwd_std_pkt_size(flow);
    double fwd_avg_iat  = flow_fwd_avg_iat(flow);
    double fwd_std_iat  = flow_fwd_std_iat(flow);

    double rev_avg_pkt  = flow_rev_avg_pkt_size(flow);
    double rev_std_pkt  = flow_rev_std_pkt_size(flow);
    double rev_avg_iat  = flow_rev_avg_iat(flow);
    double rev_std_iat  = flow_rev_std_iat(flow);

    double duration     = flow_duration(flow);

    uint64_t total_packets = flow->fwd_total_packets + flow->rev_total_packets;
    uint64_t total_bytes   = flow->fwd_total_bytes   + flow->rev_total_bytes;

    double fwd_rev_pkt_ratio  = (double)flow->fwd_total_packets /
                                 (double)(flow->rev_total_packets > 0 ? flow->rev_total_packets : 1);
    double fwd_rev_byte_ratio = (double)flow->fwd_total_bytes /
                                 (double)(flow->rev_total_bytes > 0 ? flow->rev_total_bytes : 1);

    uint32_t fwd_min = (flow->fwd_total_packets > 0) ? flow->fwd_min_pkt_size : 0;
    uint32_t rev_min = (flow->rev_total_packets > 0) ? flow->rev_min_pkt_size : 0;

    fprintf(file,
        "%s,%s,%u,%u,%u,"
        "%llu,%llu,%.4f,%.4f,%u,%u,%.6f,%.6f,"
        "%u,%u,%u,%u,%u,"
        "%llu,%llu,%.4f,%.4f,%u,%u,%.6f,%.6f,"
        "%u,%u,%u,%u,%u,"
        "%.6f,"
        "%llu,%llu,"
        "%.4f,%.4f,"
        "%u,%u,%u,%.4f,"
        "%u,%u,%u,%u,"
        "%s,normal\n",
        src_buf, dst_buf,
        (unsigned)flow->initiator_port,
        (unsigned)flow->responder_port,
        (unsigned)flow->key.protocol,
        /* fwd */
        (unsigned long long)flow->fwd_total_packets,
        (unsigned long long)flow->fwd_total_bytes,
        fwd_avg_pkt, fwd_std_pkt, fwd_min, flow->fwd_max_pkt_size,
        fwd_avg_iat, fwd_std_iat,
        flow->fwd_syn_count, flow->fwd_ack_count,
        flow->fwd_fin_count, flow->fwd_rst_count, flow->fwd_psh_count,
        /* rev */
        (unsigned long long)flow->rev_total_packets,
        (unsigned long long)flow->rev_total_bytes,
        rev_avg_pkt, rev_std_pkt, rev_min, flow->rev_max_pkt_size,
        rev_avg_iat, rev_std_iat,
        flow->rev_syn_count, flow->rev_ack_count,
        flow->rev_fin_count, flow->rev_rst_count, flow->rev_psh_count,
        /* totale si durata */
        duration,
        (unsigned long long)total_packets,
        (unsigned long long)total_bytes,
        fwd_rev_pkt_ratio, fwd_rev_byte_ratio,
        /* graph */
        flow->unique_dst_ips, flow->unique_dst_ports,
        flow->connection_degree, flow->dst_entropy,
        /* derived */
        (unsigned)flow->is_standard_port,
        (unsigned)flow->is_internal_only,
        (unsigned)flow->is_night_traffic,
        (unsigned)flow->is_known_pair,
        flow->device_type
    );
}

void csv_writer_close(FILE *file)
{
    if (file) {
        fclose(file);
    }
}

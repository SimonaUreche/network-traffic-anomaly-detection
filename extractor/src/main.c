#include "csv_writer.h"
#include "flow_table.h"
#include "packet_parser.h"
#include "graph_window.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLOW_TIMEOUT 60.0 
#define GRAPH_WINDOW 60.0
#define MAX_COMPLETED 4096

int main(int argc, char *argv[]){
    if (argc != 4) {
        fprintf(stderr,
            "Usage: ./extractor <input.pcap> <device_type> <output.csv>\n"
            "Example: ./extractor iot_sensor.pcap iot_sensor out.csv\n");
        return 1;
    }

    const char *pcap_file = argv[1];
    const char *device_type = argv[2];
    const char *csv_file = argv[3];

    //decshid .pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    //deschid csv
    FILE *csv = csv_writer_open(csv_file);
    if (!csv) {
        fprintf(stderr, "Error opening CSV: %s\n", csv_file);
        pcap_close(handle);
        return 1;
    }

    flow_table_init();
    graph_window_init(GRAPH_WINDOW);

    int datalink_type = pcap_datalink(handle);

    FlowStats completed[MAX_COMPLETED];
    int n_completed = 0;

    //citim pachetele unul cate unul
    struct pcap_pkthdr *header;
    const unsigned char *data;
    int status;

    while((status = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (status == 0) continue; // timeout, nu avem pachet nou, continuam sa asteptam

        ParsedPacket pkt;
        if (!parse_packet(header, data, datalink_type, &pkt)) {
            fprintf(stderr, "Warning: failed to parse packet at %f\n", pkt.timestamp);
            continue; // pachet invalid sau necunoscut, il sarim
        }

        flow_table_process_packet(&pkt, device_type, completed, &n_completed);

        for (int i = 0; i < n_completed; i++) {
            csv_writer_write(csv, &completed[i]);
        }

        flow_table_collect_expired(pkt.timestamp, FLOW_TIMEOUT, completed, &n_completed);
        for(int i = 0; i < n_completed; i++) {
            csv_writer_write(csv, &completed[i]);
        }
    }

    if (status == -1) {
    fprintf(stderr, "Error reading PCAP: %s\n", pcap_geterr(handle));
    }

    flow_table_flush_all(completed, &n_completed);
    for(int i = 0; i < n_completed; i++) {
        csv_writer_write(csv, &completed[i]);
    }

    csv_writer_close(csv);
    pcap_close(handle);

    fprintf(stdout, "Output: %s\n", csv_file);
    return 0;
}

     


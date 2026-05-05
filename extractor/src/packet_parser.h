#pragma once
#include <stdint.h>
#include <pcap.h> 

// rezultatul parsarii unui singuir pachet din .pcap
typedef struct {
    double timestamp; // timestamp-ul la care a fost capturat pachetul
    uint32_t src_ip; // adresa IP sursa 
    uint32_t dst_ip; // adresa IP destinatie 
    uint16_t src_port; // portul sursa
    uint16_t dst_port; // portul destinatie
    uint8_t protocol; // protocolul IPPROTOTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1
    uint32_t packet_length; // lungimea totala a pachetului
    uint8_t tcp_flags; //SYN=0x02 ACK=0x10 FIN=0x01 RST=0x04 PSH=0x08
} ParsedPacket;

//returnam 1 daca parsarea a reusit, 0 daca pachetul nu e valid
int parse_packet(const struct pcap_pkthdr *header, const unsigned char *data, int datalink_type,ParsedPacket *out);
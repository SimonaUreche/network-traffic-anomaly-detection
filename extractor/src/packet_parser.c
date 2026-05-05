#include "packet_parser.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

static int get_ip_offset(int datalink_type)
{
    switch (datalink_type) {
        case DLT_EN10MB:     return 14;  /* Ethernet */
        case DLT_LINUX_SLL:  return 16;  /* Linux cooked v1 */
        case DLT_LINUX_SLL2: return 20;  /* Linux cooked v2 - Docker */
        default:             return -1;
    }
}

int parse_packet(const struct pcap_pkthdr *header, const unsigned char *data, int datalink_type, ParsedPacket *out) {
    //gasim unde incepe headerul de IP in functie de tipul de datalink
    int ip_offset = get_ip_offset(datalink_type);
    if (ip_offset < 0) {
        return 0; // tip de datalink necunoscut, nu putem parsa
    }

    //verificam daca avem suficienti bytes pentru a citi headerul de IP
    if (header->caplen < (unsigned)(ip_offset + sizeof(struct ip))) {
        return 0; // nu avem suficienti bytes pentru a citi headerul de IP
    }

    const struct ip *ip_header = (const struct ip *)(data + ip_offset);
    
    //acceptam doar pachete IPv4
    if (ip_header->ip_v != 4) {
        return 0; // nu este un pachet IPv4
    }  

    int ip_header_length = ip_header->ip_hl * 4; // lungimea headerului de IP in bytes
    if (ip_header_length < 20) {
        return 0; // headerul de IP este prea scurt pentru a fi valid
    }

    int transport_offset = ip_offset + ip_header_length; // offset-ul unde incepe headerul de transport (TCP/UDP/ICMP)

    //completam campurile comune din structura ParsedPacket
    out->timestamp = header->ts.tv_sec + header->ts.tv_usec / 1e6; // convertim timestamp-ul in secunde cu zecimale
    out->src_ip = ip_header->ip_src.s_addr; // adresa IP sursa
    out->dst_ip = ip_header->ip_dst.s_addr; // adresa IP destinatie
    out->protocol = ip_header->ip_p; // protocolul (TCP=6, UDP=17, ICMP=1)
    out->packet_length = header->len; // lungimea totala a pachetului
    out->src_port = 0; // initializam porturile cu 0, le vom completa doar pentru TCP/UDP
    out->dst_port = 0;
    out->tcp_flags = 0; // initializam tcp_flags cu 0, le vom completa doar pentru TCP

    //extra pors si flags in functie de protocol
    if(ip_header->ip_p == IPPROTO_TCP) {
        //verificam daca avem suficienti bytes pentru a citi headerul de TCP
        if (header->caplen < (unsigned)(transport_offset + sizeof(struct tcphdr))) {
            return 0; 
        }

        const struct tcphdr *tcp_header = (const struct tcphdr *)(data + transport_offset);
        out->src_port = ntohs(tcp_header->th_sport); 
        out->dst_port = ntohs(tcp_header->th_dport); 
        out->tcp_flags = tcp_header->th_flags; 

    } else if (ip_header->ip_p == IPPROTO_UDP) {
        //verificam daca avem suficienti bytes pentru a citi headerul de UDP
        if (header->caplen < (unsigned)(transport_offset + sizeof(struct udphdr))) {
            return 0;
        }
        const struct udphdr *udp_header = (const struct udphdr *)(data + transport_offset);
        out->src_port = ntohs(udp_header->uh_sport); 
        out->dst_port = ntohs(udp_header->uh_dport); 
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        // pentru ICMP nu avem porturi, deci le lasam pe 0
    } else {
        return 0; //PROTOCAOL NECUNOSCUT, NU PARSAM
    }

    return 1; //PARSAREA A REUSIT
}
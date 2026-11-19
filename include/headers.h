#pragma once
#include <stdlib.h>
#include <netinet/in.h>

//Ethernet addresses are 6 Bytes
#define ETHER_ADDR_LEN 6

//Ethernet header
struct sniff_ethernet{
    u_char ether_dhost[ETHER_ADDR_LEN]; //destination
    u_char ether_shost[ETHER_ADDR_LEN]; //sender
    u_short ether_type;                 //IP?  ARP?  etc
};

//IP header
struct sniff_ip{
    u_char ip_vhl;                 //version << 4 | header length >> 2
    u_char ip_tos;                 //type of service
    u_short ip_len;                //total length
    u_short id;
    u_short ip_off;                //fragment offset field
#define IP_RF 0x8000               //reserved fragament flag
#define IP_DF 0x4000               //don't fragment flag
#define IP_MF 0x2000               //more frgments flag
#define IP_OFFMASK 0x1fff          //mask for fragmenting bits
    u_char ip_ttl;                 //time to live
    u_char ip_p;                   //protocol
    u_short ip_sum;                //checksum
    struct in_addr ip_src, ip_dst; //source and dest address
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

//ARP header

struct sniff_arp{
    u_short arp_htype;     //Hardware type
    u_short arp_ptype;     //Protocol type
    u_char arp_hlen;       //Hardware address length
    u_char arp_plen;       //Protocol address length
    u_short arp_oper;      //Operation code 1 - request, 2 - reply

    u_char arp_sha[6];     //Sender hardware address
    u_char arp_spa[4];     //Sender protocol address

    u_char arp_tha[6];     //Target hardware address
    u_char arp_tpa[4];     //Target protocol address
};

//TCP header
typedef u_int tcp_seq;

struct sniff_tcp{
    u_short th_sport;      //source port
    u_short th_dport;      //destination port
    tcp_seq th_seq;        //sequence number
    tcp_seq th_ack;        //acknowledgement number
    u_char th_offx2;       //data offset, rsvd
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;        //window
    u_short th_sum;        //checksum
    u_short th_urp;        //urgent pointer
};

//UDP header

struct sniff_udp{
    u_short uh_sport;      //source port
    u_short uh_dport;      //destination port
    u_short uh_ulen;       //udp length
    u_short uh_sum;        //checksum
};

//ICMP header

struct sniff_icmp {
    u_char  icmp_type;      // Tipul mesajului (ex: 8 pentru Ping, 0 pentru Reply)
    u_char  icmp_code;      // Sub-codul erorii (mai specific)
    u_short icmp_sum;       // Checksum
    
    // this depend on the type, for ping they are:
    u_short icmp_id;        // ping ID
    u_short icmp_seq;       // sequence number (ping 1, ping 2 ...)
};
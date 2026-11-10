#include <iostream>
#include <stdlib.h>
#include <pcap.h>
#include <headers.h>
#include <iomanip>

using namespace std;

//ethernet headers are always exactly 14 Bytes
#define SIZE_ETHERNET 14
#define SIZE_UDP 8
#define SIZE_ARP 28

void print_mac(const u_char *mac) {
    cout << hex << setfill('0');
    for (int i = 0; i < 6; ++i) {
        cout << setw(2) << (int)mac[i];
        if (i < 5) cout << ":";
    }
    cout << dec; // reset to decimal
}
void print_ip(const u_char* ip){
    for(int i = 0; i < 4; ++i){
        cout<<(int)ip[i];
        if(i < 3)cout << ".";
    }
}

void arp_handler(const u_char *packet){
    const struct sniff_arp* arp;
    arp = reinterpret_cast<const struct sniff_arp*>(packet + SIZE_ETHERNET);

    if (arp->arp_hlen != 6 || arp->arp_plen != 4) return; // doesn't use MAC or IPV4, ignore

    if(ntohs(arp->arp_oper) == 1)
    {
        cout << "[ARP] request: " << "tell "; 
        print_ip(arp->arp_spa);
        cout << " who has ";
        print_ip(arp->arp_tpa);
        cout << "\n";
    } else if(ntohs(arp->arp_oper) == 2){
        cout << "[ARP] reply: ";
        print_ip(arp->arp_spa);
        cout << " is at ";
        print_mac(arp->arp_sha);
        cout << "\n";
    }else return;

    (void)packet;
}

void tcp_handler(const struct sniff_ip *ip, const u_char *packet, u_int size_ip){
    const struct sniff_tcp *tcp;             //the tcp header
    

    tcp = reinterpret_cast<const struct sniff_tcp*>(packet + SIZE_ETHERNET + size_ip);
    u_int size_tcp = TH_OFF(tcp) * 4;
    if(size_tcp < 20){
        cout << "Invalid TCP header length: " << size_tcp << "\n";
        return;
    }

    //const char *payload;                     //the actual payload
    //payload = (const char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    //(void)(payload);

    string ip_source = inet_ntoa(ip->ip_src);
    string ip_dest = inet_ntoa(ip->ip_dst);

    u_short port_source = ntohs(tcp->th_sport);
    u_short port_dest = ntohs(tcp->th_dport);

    
    cout << "[TCP]  " << ip_source << ":" << port_source << " --->" <<
    ip_dest <<  ":" << port_dest << "\n";
}

void udp_handler(const struct sniff_ip *ip, const u_char *packet, u_int size_ip){
    const struct sniff_udp* udp;             //the tcp header
    
    udp = reinterpret_cast<const struct sniff_udp*>(packet + SIZE_ETHERNET + size_ip);

    string ip_source = inet_ntoa(ip->ip_src);
    string ip_dest = inet_ntoa(ip->ip_dst);

    u_short port_source = ntohs(udp->uh_sport);
    u_short port_dest = ntohs(udp->uh_dport);

    cout << "[UDP]  " << ip_source << ":" << port_source << " --->" <<
    ip_dest <<  ":" << port_dest << "\n";

}


void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet){
    (void)user_data;
    (void)header;

    const struct sniff_ethernet *ethernet;   //the ethernet header
    const struct sniff_ip *ip;               //the ip header
    
    

    u_int size_ip = 0;

    ethernet = reinterpret_cast<const struct sniff_ethernet*>(packet);
    //verify if it's an IPv4 packet
    if (ntohs(ethernet->ether_type) != 0x0800) {
        // not IP
        if(ntohs(ethernet->ether_type) == 0x806) //ARP
            arp_handler(packet); 
        return;
    }

    ip = reinterpret_cast<const struct sniff_ip*>(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if(size_ip < 20){
        cout << "Invalid IP header length: " << size_ip << "\n";
        return;
    }
    
    switch(ip->ip_p){
        case 6:
            tcp_handler(ip, packet, size_ip);
            break;

        case 17:
            udp_handler(ip, packet, size_ip);
            break;

        default:
            return;
    }
    
    (void)(ethernet);
    (void)(ip);
}

int main() {

    char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
    pcap_if_t *interface = nullptr;  /* Device to sniff on */
    pcap_t *handle;                  /* Session handle */
    struct bpf_program fp;           /* The compiled filter expression */
    char filter_exp[] = "";          /* The filter expression */
    bpf_u_int32 mask;                /* The netmask of our sniffing device */
    bpf_u_int32 net;                 /* The IP of our sniffing device */
    //struct pcap_pkthdr header;	     /* The header that pcap gives us */
    //const u_char *packet;		     /* The actual packet */

    /* Define the device */
    if (pcap_findalldevs(&interface, errbuf) == -1 || interface == nullptr){
        cerr << "didn't find an interface " << errbuf << "\n";
        pcap_freealldevs(interface);
        return 2;
    }

    cout << "Selected device: " << interface->name << "\n";

    /* Find the properties for the device */
    if (pcap_lookupnet(interface->name, &net, &mask, errbuf) == -1){
        cerr << "Can't get netmask for device " << interface->name <<"\n";
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(interface->name, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        cerr << "Couldn't open device " << interface->name << errbuf << "\n";
        pcap_freealldevs(interface);
        return 2;
    }

    //if (pcap_datalink(handle)!=DLT_EN10MB){
    //    cerr << "Device" << interface->name << " doesn't provide ethernet headers - nt supported\n";
    //    return 2;
    //}


    /* Compile and apply the filter */
    if(pcap_compile(handle, &fp, filter_exp, 0, mask) == -1){
        cerr << "Couldn't parse filter " << filter_exp << " | " << pcap_geterr(handle);
        pcap_freealldevs(interface);
        return 2;
    }
    if(pcap_setfilter(handle, &fp) == -1){
        cerr << "Couldn't install filter " << filter_exp << " | " << pcap_geterr(handle);
        pcap_freecode(&fp);
        pcap_freealldevs(interface);
        return 2;
    }
    
    pcap_freecode(&fp);

    /* Let the sniffing start */
    if (pcap_loop(handle, 1000, packet_handler, NULL) == -1) {
        cerr << "Error in pcap_loop: " << pcap_geterr(handle) << "\n";
    }
	

    pcap_close(handle);



    pcap_freealldevs(interface);

    return 0;
}
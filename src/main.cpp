#include <iostream>
#include <stdlib.h>
#include <pcap.h>
#include <headers.h>

using namespace std;

//ethernet headers are always exactly 14 Bytes
#define SIZE_ETHERNET 14

void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet){
    (void)user_data;
    (void)header;

    const struct sniff_ethernet *ethernet;   //the ethernet header
    const struct sniff_ip *ip;               //the ip header
    const struct sniff_tcp *tcp;             //the tcp header
    const char *payload;                     //the actual payload

    u_int size_ip = 0;
    u_int size_tcp = 0;

    ethernet = (struct sniff_ethernet*)(packet);
    //verify if it's an IPv4 packet
    if (ntohs(ethernet->ether_type) != 0x0800) {
        return; // not IP
    }

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if(size_ip < 20){
        cout << "Invalid IP header length: " << size_ip << "\n";
        return;
    }
    //verify if the protocol is TCP
    if (ip->ip_p != 6) { // 1 = ICMP, 6 = TCP, 17 = UDP
        return; // not TCP
    }

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if(size_tcp < 20){
        cout << "Invalid TCP header length: " << size_tcp << "\n";
        return;
    }

    payload = (const char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    cout << "Got a valid packet, IP header: " << size_ip 
         << " bytes, TCP header: " << size_tcp << " bytes.\n";
    (void)(ethernet);
    (void)(ip);
    (void)(tcp);
    (void)(payload);
}

int main() {

    char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
    pcap_if_t *interface = nullptr;  /* Device to sniff on */
    pcap_t *handle;                  /* Session handle */
    struct bpf_program fp;           /* The compiled filter expression */
    char filter_exp[] = "";   /* The filter expression */
    bpf_u_int32 mask;                /* The netmask of our sniffing device */
    bpf_u_int32 net;                 /* The IP of our sniffing device */
    struct pcap_pkthdr header;	     /* The header that pcap gives us */
    const u_char *packet;		     /* The actual packet */

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
    (void)header;
    (void)packet;

    return 0;
}
#include <iostream>
#include <stdlib.h>
#include <pcap.h>
#include <headers.h>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <ctime>
#include <vector>
#include <csignal>

using namespace std;

#define SIZE_ETHERNET 14
#define SIZE_UDP 8
#define SIZE_ARP 28
#define SIZE_ICMP 8

struct IpStats{
    time_t window_start = 0;
    int syn_count = 0;
    unordered_set<u_short> ports;
    bool scan_alerted = false;
    bool flood_alerted = false;
};

unordered_map<string,IpStats> tracker;

const int TIME_WINDOW = 5;         // 5 sec window
const size_t PORT_SCAN_LIMIT = 15; // >= 15 distinct ports in 5s => Port Scan
const int SYN_FLOOD_LIMIT = 50;    // >= 50 SYN packets in 5s => SYN Flood

vector<string> alert_log;
pcap_t *global_handle = nullptr;

string get_timestamp() {
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_r(&now, &timeinfo); // varianta thread-safe pe Linux

    char buf[20];
    strftime(buf, sizeof(buf), "%H:%M:%S", &timeinfo);
    return string(buf);
}

void handle_sigint(int signum) {
    (void)signum;
    if (global_handle != nullptr) {
        pcap_breakloop(global_handle);
    }
}

void detect_attacks(const string &ip_source, u_short port_dest, u_char flags){
    if(!(flags & TH_SYN) || (flags & TH_ACK)) return;

    time_t now = time(nullptr);

    IpStats &stats = tracker[ip_source];

    if((stats.window_start == 0) || (now - stats.window_start) >= TIME_WINDOW){
        stats.window_start = now;
        stats.syn_count = 0;
        stats.ports.clear();
        stats.scan_alerted = false;
        stats.flood_alerted = false;
    }

    stats.syn_count++;
    stats.ports.insert(port_dest);

    if (!stats.scan_alerted && stats.ports.size()>= PORT_SCAN_LIMIT){
        string msg = "[" + get_timestamp() + "] PORT SCAN from " + ip_source + " (" + to_string(stats.ports.size()) + " unique ports)";
        cout << "\033[1;31m[IDS ALERT] PORT SCAN detected from " << ip_source
             << " (" << stats.ports.size() << " unique ports in " << TIME_WINDOW << "s)\033[0m\n";
        alert_log.push_back(msg);
        stats.scan_alerted = true;
    }

    if (!stats.flood_alerted && stats.syn_count >= SYN_FLOOD_LIMIT){
        string msg = "[" + get_timestamp() + "] SYN FLOOD from " + ip_source + " (" + to_string(stats.syn_count) + " SYN packets)";
        cout << "\033[1;31m[IDS ALERT] SYN FLOOD detected from " << ip_source
             << " (" << stats.syn_count << " SYN packets in " << TIME_WINDOW << "s)\033[0m\n";
        alert_log.push_back(msg);
        stats.flood_alerted = true;
    }
}

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

    detect_attacks(ip_source, port_dest, tcp->th_flags);
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

void icmp_handler(const struct sniff_ip *ip, const u_char *packet, u_int size_ip){
    const struct sniff_icmp* icmp;        //the icmp header

    icmp = reinterpret_cast<const struct sniff_icmp*>(packet + SIZE_ETHERNET + size_ip);

    string ip_source = inet_ntoa(ip->ip_src);
    string ip_dest = inet_ntoa(ip->ip_dst);

    cout << "[ICMP] " << ip_source << " ---> " << ip_dest << " | ";

    switch(icmp->icmp_type){
        case 8:
            cout << "Echo request (ping) id=" << ntohs(icmp->icmp_id) << " seq=" << ntohs(icmp->icmp_seq) << "\n";
            break;

        case 0:
            cout << "Echo reply (pong) id=" << ntohs(icmp->icmp_id) << " seq=" << ntohs(icmp->icmp_seq) << "\n";
            break;
        
        case 3:
            cout << "Destination unreachable (code=" << (int)icmp->icmp_code << ")\n";
            break;

        case 11:
            cout << "Time exceeded (code=" << (int)icmp->icmp_code << ")\n";
            break;
        
        default:
            cout << "Type =" << (int)icmp->icmp_type << " code=" << (int)icmp->icmp_code << "\n";
            break;
    }

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
        case 1:
            icmp_handler(ip, packet, size_ip);
            break;
       
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

int main(int argc, const char *argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
    pcap_t *handle;                  /* Session handle */
    struct bpf_program fp;           /* The compiled filter expression */
    string dev_name = "";
    string filter_exp = "";

    for (int i = 1; i < argc; ++i) {
        if (string(argv[i]) == "-i") {
            if (i + 1 < argc) {
                dev_name = argv[++i];
            } else {
                cerr << "Usage: " << argv[0] << " [-i interface] [filter]\n";
                return 2;
            }
        } else {
            if (!filter_exp.empty()) {
                filter_exp += " ";
            }
            filter_exp += argv[i];
        }
    }

    bpf_u_int32 mask;                /* The netmask of our sniffing device */
    bpf_u_int32 net;                 /* The IP of our sniffing device */
    //struct pcap_pkthdr header;	     /* The header that pcap gives us */
    //const u_char *packet;		     /* The actual packet */

    /* Define the device */
    if (dev_name.empty()) {
        pcap_if_t *interface = nullptr;  /* Device to sniff on */
        if (pcap_findalldevs(&interface, errbuf) == -1 || interface == nullptr) {
            cerr << "Didn't find an interface: " << errbuf << "\n";
            return 2;
        }
        dev_name = interface->name;
        pcap_freealldevs(interface);
        interface = nullptr;
    }

    cout << "Selected device: " << dev_name << "\n";
    if (!filter_exp.empty()) {
        cout << "Applying filter: " << filter_exp << "\n";
    }

    /* Find the properties for the device */
    if (pcap_lookupnet(dev_name.c_str(), &net, &mask, errbuf) == -1){
        cerr << "Can't get netmask for device " << dev_name.c_str() <<"\n";
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev_name.c_str(), BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        cerr << "Couldn't open device " << dev_name.c_str() << errbuf << "\n";
        return 2;
    }
    global_handle = handle;
    signal(SIGINT, handle_sigint);

    //if (pcap_datalink(handle)!=DLT_EN10MB){
    //    cerr << "Device" << interface->name << " doesn't provide ethernet headers - nt supported\n";
    //    return 2;
    //}

    /* Compile and apply the filter */
    if(pcap_compile(handle, &fp, filter_exp.c_str(), 0, mask) == -1){
        cerr << "Couldn't parse filter " << filter_exp << " | " << pcap_geterr(handle);
        return 2;
    }
    if(pcap_setfilter(handle, &fp) == -1){
        cerr << "Couldn't install filter " << filter_exp << " | " << pcap_geterr(handle);
        pcap_close(handle);
        pcap_freecode(&fp);
        return 2;
    }
    
    pcap_freecode(&fp);

    /* Let the sniffing start */
    if (pcap_loop(handle, 0, packet_handler, NULL) == -1) {
        cerr << "Error in pcap_loop: " << pcap_geterr(handle) << "\n";
    }

    cout << "\n========== FINAL IDS REPORT ==========\n";
    if (alert_log.empty()) {
        cout << "No attacks detected.\n";
    } else {
        cout << "Total detected alerts: " << alert_log.size() << "\n";
        for (size_t i = 0; i < alert_log.size(); ++i) {
            cout << "  " << (i + 1) << ". " << alert_log[i] << "\n";
        }
    }
    cout << "======================================\n";

    pcap_close(handle);

    return 0;
}
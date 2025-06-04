#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <fstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <cstring>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

char src_mac[18];

void usage() {
    printf("syntax: tcp-block <interface> <pattern>\n");
    printf("sample: tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

bool get_s_mac(const char* iface, char* src_mac) {
    std::ifstream mac_file("/sys/class/net/" + std::string(iface) + "/address");
    if (!mac_file.is_open()) {
        return false;
    }
    mac_file >> src_mac;
    return true;
}

uint16_t checksum(uint16_t* ptr, int length) {
    uint32_t sum = 0;
    uint16_t odd = 0;

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }

    if (length == 1) {
        *(uint8_t *)(&odd) = (*(uint8_t *)ptr);
        sum += odd;
    }

    if (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}

void dump(char* pkt) {
    EthHdr* eth = (EthHdr*)pkt;
    IpHdr* ip = (IpHdr*)(pkt + sizeof(EthHdr));
    TcpHdr* tcp = (TcpHdr*)(pkt + sizeof(EthHdr) + ip->header_len());
    const char* data = (const char*)(pkt + sizeof(EthHdr) + ip->header_len() + tcp->header_len());

    printf("Ethernet Header\n");
    printf("  |- Destination MAC : %s\n", eth->dmac_.operator std::string().c_str());
    printf("  |- Source MAC      : %s\n", eth->smac_.operator std::string().c_str());
    printf("  |- Protocol        : %u\n", eth->type());

    printf("IP Header\n");
    printf("  |- IP Version      : %u\n", ip->ip_v);
    printf("  |- IP Header Length: %u DWORDS or %u Bytes\n", ip->header_len(), ip->header_len());
    printf("  |- Type Of Service  : %u\n", ip->dscp_and_ecn);
    printf("  |- IP Total Length   : %u Bytes(Size of Packet)\n", ntohs(ip->total_length));
    printf("  |- Identification    : %u\n", ntohs(ip->identification));
    printf("  |- TTL      : %u\n", ip->ttl);
    printf("  |- Protocol : %u\n", ip->protocol);
    printf("  |- Checksum : %u\n", ntohs(ip->checksum));
    printf("  |- Source IP        : %s\n", ip->sip().operator std::string().c_str());
    printf("  |- Destination IP   : %s\n", ip->dip().operator std::string().c_str());

    printf("TCP Header\n");
    printf("  |- Source Port      : %u\n", ntohs(tcp->sport_));
    printf("  |- Destination Port : %u\n", ntohs(tcp->dport_));
    printf("  |- Sequence Number    : %u\n", ntohl(tcp->seq_));
    printf("  |- Acknowledge Number : %u\n", ntohl(tcp->ack_));
    printf("  |- Header Length      : %u DWORDS or %u BYTES\n", tcp->hlen_ >> 4, tcp->header_len());
    printf("  |- Urgent Flag          : %u\n", (tcp->flags_ & TcpHdr::URG) >> 5);
    printf("  |- Acknowledgement Flag : %u\n", (tcp->flags_ & TcpHdr::ACK) >> 4);
    printf("  |- Push Flag            : %u\n", (tcp->flags_ & TcpHdr::PSH) >> 3);
    printf("  |- Reset Flag           : %u\n", (tcp->flags_ & TcpHdr::RST) >> 2);
    printf("  |- Synchronise Flag     : %u\n", (tcp->flags_ & TcpHdr::SYN) >> 1);
    printf("  |- Finish Flag          : %u\n", (tcp->flags_ & TcpHdr::FIN) >> 0);
    printf("  |- Window         : %u\n", ntohs(tcp->win_));
    printf("  |- Checksum       : %u\n", ntohs(tcp->sum_));
    printf("  |- Urgent Pointer : %u\n", ntohs(tcp->urp_));
    printf("  |- Payload        : %ld\n", strlen(data));
    printf("    %s\n", data);
}

void send_packet(pcap_t* pcap_handle, const char* iface, EthHdr* eth, IpHdr* ip, TcpHdr* tcp, const char* data, int recv_length, bool is_forward) {
    int eth_len = sizeof(EthHdr);
    int ip_len = sizeof(IpHdr);
    int tcp_len = sizeof(TcpHdr);
    int data_len = strlen(data);
    int packet_len = eth_len + ip_len + tcp_len + data_len;

    EthHdr new_eth;
    IpHdr new_ip;
    TcpHdr new_tcp;

    // Construct Ethernet header
    memcpy(&new_eth, eth, eth_len);
    if (!is_forward) {
        new_eth.dmac_ = eth->smac_;
    }
    new_eth.smac_ = Mac(src_mac);

    // Construct IP header
    memcpy(&new_ip, ip, ip_len);
    if (!is_forward) {
        new_ip.sip_ = ip->dip_;
        new_ip.dip_ = ip->sip_;
        new_ip.ttl = 128;
    }
    new_ip.checksum = 0;
    new_ip.total_length = htons(ip_len + tcp_len + data_len);
    new_ip.checksum = checksum((uint16_t*)&new_ip, ip_len);

    // Construct TCP header
    memcpy(&new_tcp, tcp, tcp_len);
    if (is_forward) {
        new_tcp.flags_ = TcpHdr::RST | TcpHdr::ACK;
        new_tcp.seq_ = htonl(ntohl(tcp->seq_) + recv_length);
    } else {
        new_tcp.sport_ = tcp->dport_;
        new_tcp.dport_ = tcp->sport_;
        new_tcp.flags_ = TcpHdr::FIN | TcpHdr::ACK;
        new_tcp.seq_ = tcp->ack_;
        new_tcp.ack_ = htonl(ntohl(tcp->seq_) + recv_length);
    };
    new_tcp.hlen_ = (sizeof(TcpHdr) / 4) << 4;
    new_tcp.win_ = 0;
    new_tcp.urp_ = 0;
    new_tcp.sum_ = 0;

    pseudo_header psh;
    psh.source_address = new_ip.sip_;
    psh.dest_address = new_ip.dip_;
    psh.placeholder = 0;
    psh.protocol = IpHdr::TCP;
    psh.tcp_length = htons(tcp_len + data_len);

    int buffer_len = sizeof(pseudo_header) + tcp_len + data_len;
    char* buffer = (char*)malloc(buffer_len);
    memcpy(buffer, &psh, sizeof(pseudo_header));
    memcpy(buffer + sizeof(pseudo_header), &new_tcp, tcp_len);
    memcpy(buffer + sizeof(pseudo_header) + tcp_len, data, data_len);

    new_tcp.sum_ = checksum((uint16_t*)buffer, buffer_len);

    char* pkt = (char*)malloc(packet_len);
    memcpy(pkt, &new_eth, eth_len);
    memcpy(pkt + eth_len, &new_ip, ip_len);
    memcpy(pkt + eth_len + ip_len, &new_tcp, tcp_len);
    memcpy(pkt + eth_len + ip_len + tcp_len, data, data_len);

    dump(pkt);

    if (!is_forward) {
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd < 0) {
            fprintf(stderr, "socket return %d error=%s\n", sockfd, strerror(errno));
            return;
        }

        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = new_tcp.sport_;
        sin.sin_addr.s_addr = new_ip.sip_;

        char optval = 0x01;
        setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

        if (sendto(sockfd, (unsigned char*)pkt + eth_len, packet_len - eth_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("sendto failed");
        }

        close(sockfd);
    } else {
        if (pcap_sendpacket(pcap_handle, (const u_char*)pkt, packet_len) != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", -1, pcap_geterr(pcap_handle));
        }
    }

    free(buffer);
    free(pkt);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    const char* iface = argv[1];
    const char* pattern = argv[2];

    while (!get_s_mac(iface, src_mac)) {
        printf("Failed to get source MAC address\n");
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle = pcap_open_live(iface, BUFSIZ, 1, 1, errbuf);
    if (pcap_handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", iface, errbuf);
        return -1;
    }

    struct pcap_pkthdr* header;
    const u_char* pkt;

    while (true) {
        int res = pcap_next_ex(pcap_handle, &header, &pkt);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap_handle));
            break;
        }

        EthHdr* eth = (EthHdr*)pkt;
        if (eth->type() != EthHdr::Ip4) continue;

        IpHdr* ip = (IpHdr*)(pkt + sizeof(EthHdr));
        if (ip->protocol != IpHdr::TCP) continue;

        TcpHdr* tcp = (TcpHdr*)(pkt + sizeof(EthHdr) + sizeof(IpHdr));
        int eth_len = sizeof(EthHdr);
        int ip_len = ip->header_len();
        int tcp_len = tcp->header_len();
        int payload_len = ntohs(ip->total_length) - ip_len - tcp_len;
        const char* data = (const char*)(pkt + eth_len + ip_len + tcp_len);
        const char* new_payload = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n ";

        if (strncmp(data, "GET", 3) != 0) continue;
        for (int i = 0; i < 50; i++) {
            if (strncmp(data + i, pattern, strlen(pattern)) == 0) {
                printf("Block! %s\n", pattern);

                printf("payload_len: %d\n", payload_len);

                send_packet(pcap_handle, iface, eth, ip, tcp, "", payload_len, true);
                send_packet(pcap_handle, iface, eth, ip, tcp, new_payload, payload_len, false);

                break;
            }
        }
    }

    pcap_close(pcap_handle);
    return 0;
}


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

// 전역 변수: 인터페이스의 MAC 주소 문자열을 저장
char src_mac[18];

// 사용법 출력 함수
void usage() {
    printf("syntax: tcp-block <interface> <pattern>\n");
    printf("sample: tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

// 인터페이스 이름(iface)에 대응하는 MAC 주소를 /sys 파일 시스템에서 읽어와 src_mac에 저장
bool get_s_mac(const char* iface, char* src_mac) {
    std::ifstream mac_file("/sys/class/net/" + std::string(iface) + "/address");
    if (!mac_file.is_open()) {
        return false; // 파일을 열지 못하면 false 반환
    }
    mac_file >> src_mac; // MAC 주소 문자열 읽기
    return true;
}

// 체크섬 계산 함수: ptr이 가리키는 버퍼(16비트 단위) 길이 length만큼 합산 후 1의 보수 반환
uint16_t checksum(uint16_t* ptr, int length) {
    uint32_t sum = 0;
    uint16_t odd = 0;

    // 16비트 덩어리로 합산
    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }

    // 남은 1바이트 처리(odd)
    if (length == 1) {
        *(uint8_t *)(&odd) = (*(uint8_t *)ptr);
        sum += odd;
    }

    // 오버플로우된 상위 16비트가 있으면 다시 하위 16비트에 합산
    if (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum; // one's complement 반환
}

// 디버그용: 메모리 상의 전체 패킷(Ethernet+IP+TCP+Payload)을 읽어와 구조체 멤버를 출력
void dump(char* pkt) {
    EthHdr* eth = (EthHdr*)pkt;                                  // Ethernet 헤더
    IpHdr* ip = (IpHdr*)(pkt + sizeof(EthHdr));                  // IP 헤더(이더넷 바로 뒤)
    TcpHdr* tcp = (TcpHdr*)(pkt + sizeof(EthHdr) + ip->header_len()); // TCP 헤더(IP 헤더 뒤)
    const char* data = (const char*)(pkt + sizeof(EthHdr) + ip->header_len() + tcp->header_len()); // 페이로드

    // Ethernet 헤더 정보 출력
    printf("Ethernet Header\n");
    printf("  |- Destination MAC : %s\n", eth->dmac_.operator std::string().c_str());
    printf("  |- Source MAC      : %s\n", eth->smac_.operator std::string().c_str());
    printf("  |- Protocol        : %u\n", eth->type());

    // IP 헤더 정보 출력
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

    // TCP 헤더 정보 출력
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

/*
 * send_packet:
 *   - pcap_handle: libpcap 핸들 (pcap_sendpacket 사용 시 필요)
 *   - iface: 인터페이스 이름 (예: "wlan0") - 현재 코드는 주로 pcap_handle로 전송
 *   - eth, ip, tcp: 캡처된 원래 패킷의 헤더 포인터
 *   - data: 전송할 TCP 페이로드(예: HTTP 302 Redirect 문자열)
 *   - recv_length: 원래 패킷의 TCP 페이로드 길이 (시퀀스/ACK 계산에 사용)
 *   - is_forward: true → 서버로 향하는 RST+ACK, false → 클라이언트로 향하는 FIN+ACK+리다이렉션
 */
void send_packet(pcap_t* pcap_handle, const char* iface,
                 EthHdr* eth, IpHdr* ip, TcpHdr* tcp,
                 const char* data, int recv_length, bool is_forward) {
    // 헤더 크기와 데이터 길이 계산
    int eth_len = sizeof(EthHdr);
    int ip_len = sizeof(IpHdr);
    int tcp_len = sizeof(TcpHdr);
    int data_len = strlen(data);
    int packet_len = eth_len + ip_len + tcp_len + data_len;

    EthHdr new_eth;  // 수정된 Ethernet 헤더
    IpHdr new_ip;    // 수정된 IP 헤더
    TcpHdr new_tcp;  // 수정된 TCP 헤더

    // 1) Ethernet 헤더 구성
    memcpy(&new_eth, eth, eth_len);      // 원래 Ethernet 헤더 복사
    if (!is_forward) {
        // is_forward == false일 경우(클라이언트로 보내는 역방향 패킷),
        // 목적지 MAC을 원래의 출발지 MAC(클라이언트 MAC)으로 변경
        new_eth.dmac_ = eth->smac_;
    }
    // 출발지 MAC은 항상 이 인터페이스의 MAC으로 설정
    new_eth.smac_ = Mac(src_mac);

    // 2) IP 헤더 구성
    memcpy(&new_ip, ip, ip_len); // 원래 IP 헤더 복사
    if (!is_forward) {
        // 역방향일 때(클라이언트로 보낼 때),
        // IP 출발지/목적지를 서로 바꿔서 클라이언트로 돌아가도록 설정
        new_ip.sip_ = ip->dip_;
        new_ip.dip_ = ip->sip_;
        new_ip.ttl = 128; // TTL을 기본값으로 설정
    }
    // IP 체크섬 다시 계산: 먼저 0으로 초기화하고, total_length 설정 후 재계산
    new_ip.checksum = 0;
    new_ip.total_length = htons(ip_len + tcp_len + data_len);
    new_ip.checksum = checksum((uint16_t*)&new_ip, ip_len);

    // 3) TCP 헤더 구성
    memcpy(&new_tcp, tcp, tcp_len); // 원래 TCP 헤더 복사
    if (is_forward) {
        // 전방향: 서버로 보내는 RST+ACK 패킷 → 세션 강제 종료
        new_tcp.flags_ = TcpHdr::RST | TcpHdr::ACK;
        // 시퀀스 번호는 원래 시퀀스 + 원래 페이로드 길이
        new_tcp.seq_ = htonl(ntohl(tcp->seq_) + recv_length);
    } else {
        // 역방향: 클라이언트로 보내는 FIN+ACK(HTTP 302 Redirect)
        new_tcp.sport_ = tcp->dport_; // 서버 포트 → 클라이언트 포트
        new_tcp.dport_ = tcp->sport_; // 클라이언트 포트 → 서버 포트
        new_tcp.flags_ = TcpHdr::FIN | TcpHdr::ACK;
        // 시퀀스/ACK 번호 계산
        new_tcp.seq_ = tcp->ack_;
        new_tcp.ack_ = htonl(ntohl(tcp->seq_) + recv_length);
    }
    // TCP 헤더 길이를 20바이트(5 * 4) 단위로 설정
    new_tcp.hlen_ = (sizeof(TcpHdr) / 4) << 4;
    new_tcp.win_ = 0; // 윈도우 크기 0
    new_tcp.urp_ = 0; // 긴급 포인터 0
    new_tcp.sum_ = 0; // 체크섬 계산 전 0으로 초기화

    // 4) pseudo-header 구성 (체크섬 계산용)
    pseudo_header psh;
    psh.source_address = new_ip.sip_;       // IP 출발지
    psh.dest_address   = new_ip.dip_;       // IP 목적지
    psh.placeholder    = 0;                 // 항상 0
    psh.protocol       = IpHdr::TCP;        // 프로토콜 번호(6)
    psh.tcp_length     = htons(tcp_len + data_len); // TCP 헤더+데이터 길이

    // pseudo-header + TCP 헤더 + 데이터 순으로 버퍼에 복사
    int buffer_len = sizeof(pseudo_header) + tcp_len + data_len;
    char* buffer = (char*)malloc(buffer_len);
    memcpy(buffer, &psh, sizeof(pseudo_header));
    memcpy(buffer + sizeof(pseudo_header), &new_tcp, tcp_len);
    memcpy(buffer + sizeof(pseudo_header) + tcp_len, data, data_len);

    // 체크섬 계산 및 new_tcp.sum_에 저장
    new_tcp.sum_ = checksum((uint16_t*)buffer, buffer_len);

    // 5) 최종 패킷 버퍼 생성(Ethernet | IP | TCP | 데이터)
    char* pkt = (char*)malloc(packet_len);
    memcpy(pkt, &new_eth, eth_len);
    memcpy(pkt + eth_len, &new_ip, ip_len);
    memcpy(pkt + eth_len + ip_len, &new_tcp, tcp_len);
    memcpy(pkt + eth_len + ip_len + tcp_len, data, data_len);

    // 디버그: newly constructed packet dump 출력
    dump(pkt);

    // 6) 패킷 전송
    if (!is_forward) {
        // 역방향: Raw Socket 사용 (IP 헤더 포함)
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd < 0) {
            fprintf(stderr, "socket return %d error=%s\n", sockfd, strerror(errno));
            free(buffer);
            free(pkt);
            return;
        }

        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = new_tcp.sport_;          // 목적지 포트 (클라이언트 포트)
        sin.sin_addr.s_addr = new_ip.sip_;      // 목적지 IP (클라이언트 IP)

        // IP_HDRINCL 옵션 설정 → IP 헤더 직접 포함
        char optval = 0x01;
        setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

        // Ethernet 헤더(offset eth_len) 제외하고 IP 레벨부터 전송
        if (sendto(sockfd, (unsigned char*)pkt + eth_len,
                   packet_len - eth_len, 0,
                   (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("sendto failed");
        }

        close(sockfd);
    } else {
        // 전방향: libpcap 사용하여 Ethernet 레벨로 전송
        if (pcap_sendpacket(pcap_handle, (const u_char*)pkt, packet_len) != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n",
                    -1, pcap_geterr(pcap_handle));
        }
    }

    free(buffer);
    free(pkt);
}

int main(int argc, char* argv[]) {
    // 1) 인자 개수 검사: <interface> <pattern> 두 개 인자가 필요
    if (argc != 3) {
        usage();
        return -1;
    }

    const char* iface = argv[1];   // 네트워크 인터페이스 이름
    const char* pattern = argv[2]; // 차단할 문자열 패턴 (예: "Host: example.com")

    // 2) 인터페이스의 MAC 주소 읽어오기 (성공할 때까지 반복)
    while (!get_s_mac(iface, src_mac)) {
        printf("Failed to get source MAC address\n");
    }

    // 3) libpcap으로 인터페이스 열기 (promiscuous 모드, 타임아웃 1ms)
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle = pcap_open_live(iface, BUFSIZ, 1, 1, errbuf);
    if (pcap_handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", iface, errbuf);
        return -1;
    }

    struct pcap_pkthdr* header;
    const u_char* pkt;

    // 4) 무한 루프: 패킷 하나씩 읽어 검사
    while (true) {
        int res = pcap_next_ex(pcap_handle, &header, &pkt);
        if (res == 0) continue; // 타임아웃, 다시 반복
        if (res == -1 || res == -2) {
            // 에러 혹은 캡처 종료
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap_handle));
            break;
        }

        // 4-1) Ethernet 헤더 검사: IPv4 패킷이 아니면 무시
        EthHdr* eth = (EthHdr*)pkt;
        if (eth->type() != EthHdr::Ip4) continue;

        // 4-2) IP 헤더 검사: TCP가 아니면 무시
        IpHdr* ip = (IpHdr*)(pkt + sizeof(EthHdr));
        if (ip->protocol != IpHdr::TCP) continue;

        // 4-3) TCP 헤더와 페이로드 위치 계산
        TcpHdr* tcp = (TcpHdr*)(pkt + sizeof(EthHdr) + sizeof(IpHdr));
        int eth_len = sizeof(EthHdr);
        int ip_len = ip->header_len();
        int tcp_len = tcp->header_len();
        int payload_len = ntohs(ip->total_length) - ip_len - tcp_len; // 페이로드 길이
        const char* data = (const char*)(pkt + eth_len + ip_len + tcp_len);

        // 4-4) HTTP GET 요청인지 확인 (페이로드 시작 3바이트가 "GET"인지)
        if (strncmp(data, "GET", 3) != 0) continue;

        // 4-5) 지정한 패턴(pattern)이 GET 요청 헤더 내에 있는지 최대 50바이트까지 검색
        const char* new_payload = 
            "HTTP/1.0 302 Redirect\r\n"
            "Location: http://warning.or.kr\r\n"
            "\r\n ";

        for (int i = 0; i < 50; i++) {
            if (strncmp(data + i, pattern, strlen(pattern)) == 0) {
                // 패턴이 발견되면 차단 동작 수행
                printf("Block! %s\n", pattern);
                printf("payload_len: %d\n", payload_len);

                // 4-6) 서버로 향하는 전방향 패킷에 RST+ACK 보내 세션 강제 종료
                send_packet(pcap_handle, iface, eth, ip, tcp,
                            "", payload_len, true);

                // 4-7) 클라이언트로 향하는 역방향 패킷에 FIN+ACK + HTTP 302 Redirect 전송
                send_packet(pcap_handle, iface, eth, ip, tcp,
                            new_payload, payload_len, false);

                break;
            }
        }
    }

    // 5) pcap 핸들 닫고 종료
    pcap_close(pcap_handle);
    return 0;
}

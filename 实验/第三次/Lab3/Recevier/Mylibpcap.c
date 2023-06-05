#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <time.h>

#define MAX_PACKET_SIZE 65536
#define DEVICE_NAME "ens33"

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 net;
    bpf_u_int32 mask;
    FILE *fpout;
    char filename[50];

    // 打开网络接口
    handle = pcap_open_live(DEVICE_NAME, MAX_PACKET_SIZE, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        exit(1);
    }

    // 获取网络接口地址和掩码
    if (pcap_lookupnet(DEVICE_NAME, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device eth0\n");
        net = 0;
        mask = 0;
    }

    // 编译过滤器
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(1);
    }

    // 设置过滤器
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(1);
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(filename, sizeof(filename), "%Y%m%d-%H-%M-%S.txt", tm_info);

    // 打开输出文件
    fpout = fopen(filename, "w");
    if (fpout == NULL) {
        fprintf(stderr, "Failed to create output file\n");
        exit(1);
    }

    // 开始捕获数据包
    pcap_loop(handle, 0, packet_handler, (u_char *)fpout);

    // 关闭输出文件
    fclose(fpout);

    // 关闭网络接口
    pcap_close(handle);

    return 0;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    // 以太网头部长度
    int ethernet_header_length = 14;

    // 以太网头部
    struct ether_header *ethernet_header;
    ethernet_header = (struct ether_header *) packet;

    // IP 数据包
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
        // IP 头部长度
        int ip_header_length;
        struct ip *ip_header;
        ip_header = (struct ip *) (packet + ethernet_header_length);
        ip_header_length = ip_header->ip_hl * 4;
    	char src_ip[INET_ADDRSTRLEN];
    	char dst_ip[INET_ADDRSTRLEN];
    	inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    	inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        // TCP 数据包
        if (ip_header->ip_p == IPPROTO_TCP) {
            // TCP 头部长度
            int tcp_header_length;
            struct tcphdr *tcp_header;
            tcp_header = (struct tcphdr *) (packet + ethernet_header_length + ip_header_length);
            tcp_header_length = tcp_header->th_off * 4;

            // 输出四元组和协议类型
            fprintf((FILE *)user, "TCP %s:%d -> %s:%d\n",
                src_ip, ntohs(tcp_header->th_sport),
                dst_ip, ntohs(tcp_header->th_dport));
        }
        // UDP 数据包
        else if (ip_header->ip_p == IPPROTO_UDP) {
            // UDP 头部长度
            int udp_header_length;
            struct udphdr *udp_header;
            udp_header = (struct udphdr *) (packet + ethernet_header_length + ip_header_length);
            udp_header_length = sizeof(struct udphdr);

            // 输出四元组和协议类型
            fprintf((FILE *)user, "UDP %s:%d -> %s:%d\n",
                src_ip, ntohs(udp_header->uh_sport),
                dst_ip, ntohs(udp_header->uh_dport));
        }
    }
}

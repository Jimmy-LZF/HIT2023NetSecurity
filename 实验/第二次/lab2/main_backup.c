#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
// #include <arpa/inet.h>
// #include <linux/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
int main()
{
    char filename[50];
    snprintf(filename, sizeof(filename), "output_%ld.txt", time(NULL));  // 生成新的文件名

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip";  // 过滤规则，只捕获IP数据包
    bpf_u_int32 net;
    bpf_u_int32 mask;

    if (pcap_lookupnet("lo", &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Cannot get netmask for device %s\n", "lo");
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);  // 捕获本地网络接口
    if (handle == NULL) {
        fprintf(stderr, "Cannot open device %s: %s\n", "lo", errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Cannot parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Cannot install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, process_packet, (u_char *)filename);  // 进入捕获循环

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    FILE *fp;
    fp = fopen((char *)args, "a");  // 打开输出文件

    int size = header->len;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));  // 获取IP头部指针
    struct sockaddr_in src, dst;
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    src.sin_addr.s_addr = iph->saddr;
    dst.sin_addr.s_addr = iph->daddr;

    if (iph->protocol == IPPROTO_TCP) {  // 只处理TCP协议的数据包
        const struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));  // 获取TCP头部指针
        fprintf(fp, "Source IP: %s\n", inet_ntoa(src.sin_addr));
        fprintf(fp, "Destination IP: %s\n", inet_ntoa(dst.sin_addr));
        fprintf(fp, "Source port: %u\n", ntohs(tcph->source));
        fprintf(fp, "Destination port: %u\n\n", ntohs(tcph->dest));

        /*struct timeval tv[2];  // 定义时间结构体
        tv[0].tv_sec = header->ts.tv_sec;  // 记录捕获时间
        tv[0].tv_usec = header->ts.tv_usec;
        tv[1].tv_sec = header->ts.tv_sec;
        tv[1].tv_usec = header->ts.tv_usec;
        utimes(args, tv);  // 更新文件访问和修改时间*/
    }

    fclose(fp);  // 关闭输出文件
}

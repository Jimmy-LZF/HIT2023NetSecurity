#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    // 获取网络接口列表
    pcap_if_t *interfaces;
    if (pcap_findalldevs(&interfaces, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get network interfaces: %s\n", errbuf);
        return -1;
    }

    // 获取第一个网络接口
    const char *dev = "ens33";
    // 获取网络地址和掩码
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // 释放网络接口列表
    pcap_freealldevs(interfaces);

    printf("Using device %s\n", dev);

    // 打开网络接口
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    // 编译过滤规则
    if (pcap_compile(handle, &fp, "ip", 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", "ip", pcap_geterr(handle));
        return -1;
    }

    // 应用过滤规则
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", "ip", pcap_geterr(handle));
        return -1;
    }

    // 开始捕获数据包
    pcap_loop(handle, -1, process_packet, NULL);

    // 关闭网络接口
    pcap_close(handle);

    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;
    if (ntohs(eth->h_proto) != ETH_P_IP)
    {
        // 非 IPv4 数据包，忽略
        return;
    }

    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);

    if (ip->protocol != IPPROTO_TCP)
    {
        // 非 TCP 数据包，忽略
        return;
    }

    struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    uint16_t src_port = ntohs(tcp->source);
    uint16_t dst_port = ntohs(tcp->dest);

    // 以当前时间为文件名，将四元组写入文件
    time_t t = time(NULL);

    struct tm *time_now = localtime(&t);
    char filename[64];
    snprintf(filename, sizeof(filename), "%04d%02d%02d%02d%02d%02d.txt",
             time_now->tm_year + 1900, time_now->tm_mon + 1, time_now->tm_mday,
             time_now->tm_hour, time_now->tm_min, time_now->tm_sec);

    FILE *fp = fopen(filename, "a");
    if (fp == NULL)
    {
        perror("fopen");
        return;
    }

    fprintf(fp, "Source IP: %s\n", src_ip);
    fprintf(fp, "Destination IP: %s\n", dst_ip);
    fprintf(fp, "Source port: %u\n", src_port);
    fprintf(fp, "Destination port: %u\n", dst_port);

    fclose(fp);
}



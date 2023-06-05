#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <stdint.h>

#define CONFIG_FILE "config.txt"
#define PAYLOAD_FILE "payload.txt"
#define MAX_PAYLOAD_SIZE 2048

int main(int argc, char **argv)
{
    libnet_t *l;
    libnet_ptag_t udp, ipv4;
    uint32_t payload_s;
    char errbuf[LIBNET_ERRBUF_SIZE];
    uint32_t src_ip, dst_ip;
    unsigned short src_port, dst_port;

    FILE *fp;
    char line[256];
    // 读取配置文件，设置 源\目的 ip\port
    fp = fopen(CONFIG_FILE, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open config file %s\n", CONFIG_FILE);
        exit(EXIT_FAILURE);
    }

    if (fgets(line, sizeof(line), fp) == NULL) {
        fprintf(stderr, "Failed to read from config file %s\n", CONFIG_FILE);
        exit(EXIT_FAILURE);
    }

    // 读取源ip\port
    sscanf(line, "%hhu.%hhu.%hhu.%hhu %hu", 
    &((uint8_t*)&src_ip)[0], &((uint8_t*)&src_ip)[1], 
    &((uint8_t*)&src_ip)[2], &((uint8_t*)&src_ip)[3], 
    &src_port);

    if (fgets(line, sizeof(line), fp) == NULL) {
        fprintf(stderr, "Failed to read from config file %s\n", CONFIG_FILE);
        exit(EXIT_FAILURE);
    }

    //读取目的ip\port
    sscanf(line, "%hhu.%hhu.%hhu.%hhu %hu", 
        &((uint8_t*)&dst_ip)[0], &((uint8_t*)&dst_ip)[1], 
        &((uint8_t*)&dst_ip)[2], &((uint8_t*)&dst_ip)[3], 
        &dst_port);

    fclose(fp);

    // 打印读取的ip地址、端口号
    printf("Source IP: %hhu.%hhu.%hhu.%hhu\n", 
        ((uint8_t*)&src_ip)[0], ((uint8_t*)&src_ip)[1], 
        ((uint8_t*)&src_ip)[2], ((uint8_t*)&src_ip)[3]);
    printf("Source Port: %hu\n", src_port);

    printf("Destination IP: %hhu.%hhu.%hhu.%hhu\n", 
        ((uint8_t*)&dst_ip)[0], ((uint8_t*)&dst_ip)[1], 
        ((uint8_t*)&dst_ip)[2], ((uint8_t*)&dst_ip)[3]);
    printf("Destination Port: %hu\n", dst_port);

    // 初始化libnet
    l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    // 打开payload.txt
    fp = fopen(PAYLOAD_FILE, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open payload file %s\n", PAYLOAD_FILE);
        exit(EXIT_FAILURE);
    }

    // 读取文件内容
    u_int8_t payload[MAX_PAYLOAD_SIZE];
    payload_s = fread(payload, 1, MAX_PAYLOAD_SIZE, fp);

    // 打印文件内容
    printf("Sending payload:\n");
    for (int i = 0; i < payload_s; i++) {
    printf("%c", payload[i]);
    }
    fclose(fp);

    // 创建udp数据包
    udp = libnet_build_udp(
            src_port,                       /* source port */
            dst_port,                       /* destination port */
            LIBNET_UDP_H + payload_s,       /* packet length */
            0,                              /* checksum */
            payload,                        /* payload */
            payload_s,                      /* payload size */
            l,                              /* libnet handle */
            0                               /* new protocol tag */
            );
    if (udp == -1) {
        fprintf(stderr, "libnet_build_udp() failed: %s\n", libnet_geterror(l));
        goto bad;
    }

    // 创建ip数据包
    ipv4 = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_UDP_H + payload_s, /* packet length */
            0,                                      /* TOS */
            libnet_get_prand(LIBNET_PRu16),          /* IP ID */
            0,                                      /* IP Frag */
            64,                                     /* TTL */
            IPPROTO_UDP,                            /* protocol */
            0,                                      /* checksum */
            src_ip,                                 /* source IP */
            dst_ip,                                 /* destination IP */
            NULL,                                   /* payload */
            0,                                      /* payload size */
            l,                                      /* libnet handle */
            0                                       /* new protocol tag */
            );
    if (ipv4 == -1) {
        fprintf(stderr, "libnet_build_ipv4() failed: %s\n", libnet_geterror(l));
        goto bad;
    }

    if (libnet_write(l) == -1) {
        fprintf(stderr, "libnet_write() failed: %s\n", libnet_geterror(l));
        goto bad;
    }

    printf("\nPacket sent successfully!\n");

    libnet_destroy(l);
    return 0;

bad:
    libnet_destroy(l);
    exit(EXIT_FAILURE);
}
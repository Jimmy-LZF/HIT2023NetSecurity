#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h> // Linux系统需要使用这个头文件
// #include <winsock2.h> // Windows系统需要使用这个头文件

#define MAX_BUFFER_SIZE 2048
#define PORT 54321


void recvUDP() {
    char *ip_addr = "0.0.0.0"; // 监听所有网络接口
    uint16_t port = PORT; // 监听的端口号

    // 创建UDP套接字
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    // 绑定套接字到IP地址和端口号
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind() failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 接收数据包
    char buffer[MAX_BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, &client_addr_len);
    if (bytes_received < 0) {
        perror("recvfrom() failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 获取套接字的本地地址信息
    struct sockaddr_in local_addr;
    socklen_t local_addr_len = sizeof(local_addr);
    if (getsockname(sockfd, (struct sockaddr *)&local_addr, &local_addr_len) < 0) {
        perror("getsockname() failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Local address: %s:%d\n", inet_ntoa(local_addr.sin_addr), ntohs(local_addr.sin_port));

    // 打印接收到的数据和目的IP地址和端口号
    char client_ip[INET_ADDRSTRLEN];
    char local_ip[INET_ADDRSTRLEN];
    printf("Received %d bytes: %s:%d -> %s:%d\n", bytes_received, 
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN), ntohs(client_addr.sin_port), 
        inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, INET_ADDRSTRLEN), ntohs(local_addr.sin_port));
    printf("Data: \n%s\n", buffer);

    // 关闭套接字
    close(sockfd);
}

int main(){
    while (1)
    {
        recvUDP();
    }
    return 0;
}
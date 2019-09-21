#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct UdpHead
{
    short src_port;
    short dest_port;
    short len;
    short checksum;
};

struct IpHead
{
    unsigned char ver;
    unsigned char tos;
    short total_len;
    short id;
    short flags;
    unsigned char ttl;
    unsigned char protocol;
    short checksum;
    int IPsrc;
    int IPdst;
};

int main()
{
    char buf[] = "HI!\n";
    char buf2[128];
    char message[128];
    struct sockaddr_in addr, server_addr;
    int sock, bytes_read, val = 1, cycle = 1, size = sizeof(server_addr);
    struct UdpHead udp_header;
    struct IpHead ip_header;
    short port;
    
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sock < 0)
    {
        perror("sock");
        exit(-1);
    }
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    
    udp_header.src_port = htons(12345);
    udp_header.dest_port = htons(3333);
    udp_header.len = htons(sizeof(udp_header) + sizeof(buf));
    udp_header.checksum = 0;
    
    ip_header.ver = 0b01000101;
    ip_header.tos = 0;
    ip_header.total_len = 0;
    ip_header.id = 0;
    ip_header.flags = 0;
    ip_header.ttl = 64;
    ip_header.protocol = 17;
    ip_header.checksum = 0;
    ip_header.IPsrc = 0;
    ip_header.IPdst = htonl(INADDR_LOOPBACK);
    
    memcpy(message, (char *)&ip_header, sizeof(ip_header));
    memcpy(message + sizeof(ip_header), (char *)&udp_header, sizeof(udp_header));
    memcpy(message + sizeof(ip_header) + sizeof(udp_header), buf, sizeof(buf));
    sendto(sock, message, sizeof(ip_header) + sizeof(udp_header) + sizeof(buf), 0, (struct sockaddr *)&addr, sizeof(addr));
    while(cycle)
    {
        if(bytes_read = recv(sock, buf2, sizeof(buf2), 0) < 0)
        {
            perror("recv");
            exit(-1);
        }
        port = ntohs(*((int *)(buf2 + 22)));
        if(port == 12345)
        {
            cycle = 0;
            printf("CLIENT: form %d , message: %s\n", port, buf2 + 28);
        }
    }
    close(sock);
    exit(0);
}

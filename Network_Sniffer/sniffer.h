
#ifndef _SNIFFER_
#define _SNIFFER_
#include <stdio.h>

typedef struct s_protocol
{
	int tcp;
	int udp;
	int icmp;
	int others;//其他的协议，这里只处理tcp.UDP和icmp
	int total;//数据包的总量
}t_protocol;


typedef struct s_sniffer
{
	FILE *logfile;//文件指针
	t_protocol *prot;
}t_sniffer;

static void print_tcp_packet(unsigned char *buffer,int size,t_sniffer* sniffer);
static void print_udp_packet(unsigned char *buffer,int size,t_sniffer* sniffer);
static void print_icmp_packet(unsigned char *buffer,int size,t_sniffer* sniffer);
static void print_ip_packet(unsigned char *buffer,int size,t_sniffer* sniffer);


#endif

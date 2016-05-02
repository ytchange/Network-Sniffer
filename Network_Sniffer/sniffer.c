#include "sniffer.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "sniffer.h"

void print_ip_packet(unsigned char *buffer,int size,t_sniffer* sniffer)
{
	struct iphdr *iph=(struct iphdr *)buffer;
	struct sockaddr_in source;//用来存储源地址
	struct sockaddr_in dest;//用来存储目标地址
	memset(&source,0,sizeof(source));
	memset(&dest,0,sizeof(dest));
	source.sin_addr.s_addr=iph->saddr;
	dest.sin_addr.s_addr=iph->daddr;
	fprintf(sniffer->logfile,"\n");
	fprintf(sniffer->logfile," -IP_version         :%d\n",(int)iph->version);//ip版本
	fprintf(sniffer->logfile," -IP_head_length     :%d\n",(int)(iph->ihl)*4);//首部长度是4位，4字节的
	fprintf(sniffer->logfile," -IP_type_of_server  :%d\n",(int)iph->tos);//服务类型
	fprintf(sniffer->logfile," -IP_total_length    :%d\n",ntohs(iph->tot_len));//数据报的总长度
	fprintf(sniffer->logfile," -IP_id              :%d\n",ntohs(iph->id));//标示字段，标示主机发送的每一分数据报，发一份+1
	fprintf(sniffer->logfile," -IP_time_to_live    :%d\n",(int)iph->ttl);//描述数据报的生存周期，通常为32或64，每过一个路由器减1
	fprintf(sniffer->logfile," -IP_protocol        :%d\n",(int)iph->protocol);//协议字段，标示上一层的协议是什么
	fprintf(sniffer->logfile," -IP_source_ip       :%d\n",inet_ntoa(source.sin_addr));//源ip地址
	fprintf(sniffer->logfile," -IP_destation_ip    :%d\n",inet_ntoa(dest.sin_addr));//目标IP地址
}

void print_tcp_packet(unsigned char *buffer,int size,t_sniffer *sniffer)
{
	//在buffer中获取各自的首部放在相应的结构体中
	struct iphdr *iph;
	struct tcphdr *tcph;
	//先打印ip头部信息
	print_ip_packet(buffer,size,sniffer);
	
	iph=(struct iphdr *)buffer;
	int ipLen=iph->ihl*4;//iph中的ipl成员表示的是IP首部的长度，是4字节的所以乘4
	tcph=(struct tcphdr *)(buffer+ipLen);
	//以下将tcp的首部信息写入日志文件中
	
	fprintf(sniffer->logfile,"\n");
	fprintf(sniffer->logfile,"TCP Header\n");
	fprintf(sniffer->logfile,"  -Source Port          : %u\n",ntohs(tcph->source));
	fprintf(sniffer->logfile,"  -Destination Port     : %u\n",ntohs(tcph->dest));
	fprintf(sniffer->logfile,"  -Sequence Number      : %u\n",ntohl(tcph->seq));
	fprintf(sniffer->logfile,"  -Acknowledge Number   : %u\n",ntohl(tcph->ack_seq));
	fprintf(sniffer->logfile,"  -Header Length        : %d\n",(unsigned int)tcph->doff*4);
	fprintf(sniffer->logfile,"  -Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(sniffer->logfile,"  -Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(sniffer->logfile,"  -Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(sniffer->logfile,"  -Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(sniffer->logfile,"  -Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(sniffer->logfile,"  -Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(sniffer->logfile,"  -Window               : %d\n",ntohs(tcph->window));
	fprintf(sniffer->logfile,"  -Checksum             : %d\n",ntohs(tcph->check));
	fprintf(sniffer->logfile,"  -Urgent Pointer       : %d\n",tcph->urg_ptr);
	fprintf(sniffer->logfile,"\n");
	fprintf(sniffer->logfile,"                        DATA Dump                         ");
	fprintf(sniffer->logfile,"\n");
  
	fprintf(sniffer->logfile,"IP Header\n");
	//PrintData(buffer, iphdrlen, sniffer);
  
	fprintf(sniffer->logfile,"TCP Header\n");
	//PrintData(buf+iphdrlen, tcph->doff*4, sniffer);
  
	fprintf(sniffer->logfile,"Data Payload\n");


}

void print_icmp_packet(unsigned char *buffer,int size,t_sniffer* sniffer)
{}
void print_udp_packet(unsigned char *buffer,int size,t_sniffer* sniffer)
{}

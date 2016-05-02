#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "sniffer.c"
#define	ETH_P_IP 0x800// 只接收发往本机mac的ip类型的数据帧

void ProcessPacket(unsigned char *buffer,int size,t_sniffer*sniffer)
{
	//以太网帧的格式是：前6字节是目的地址，接下来6字节是源地址，接下来2字节是上层帧格式的协议标示符，其余的是负载（上层的IP数据报）
	buffer=buffer+6+6+2;//buffer现在指向的就是IP数据报
	struct iphdr *iph=(struct iphdr*)buffer;//iphdr结构体就是描述IP数据报的结构体
	
	sniffer->prot->total++;
	//根据结构体的protocol 字段的值，判断上层的数据包类型，是tcp、udp还是ICMP
	switch(iph->protocol)
	{
		case(1)://1表示的是icmp协议
			sniffer->prot->icmp++;
			print_icmp_packet(buffer,size,sniffer);
			break;
		case(6)://6表示的是TCP协议
			sniffer->prot->tcp++;
			print_tcp_packet(buffer,size,sniffer);
			break;
		case(17)://17表示的是UDP协议
			sniffer->prot->udp++;
			print_udp_packet(buffer,size,sniffer);
			break;
		default:
			sniffer->prot->others++;
			break;
	}
	printf("[%s][%s]",__DATE__,__TIME__);
	printf("TCP : %d ,UDP : %d ,ICMP : %d ,others : %d,total : %d\n",\
			sniffer->prot->tcp,sniffer->prot->udp,sniffer->prot->icmp,\
			sniffer->prot->others,sniffer->prot->total);
}
int Respond(int sd)
{
	char buf[1024];
	memset(buf,'\0',sizeof(buf));
	int len=read(0,buf,1024);
	if(len>0)
	{
		if(strncmp(buf,"quit",4)==0)
		{
			return 1;
		}
	}
	return 0;
}
void getstart()
{
	printf("[%s][%s]",__DATE__,__TIME__);
	printf("start of network sniffer!!!\n");
	sleep(2);
}
int main()
{  
	struct sockaddr saddr;
	unsigned char *buffer;//用来保存数据包
	buffer=(unsigned char *)malloc(sizeof(unsigned char*)*65536);//因为ip数据包长度最大是16位，总大小是65536
	t_sniffer sniffer;//保存数据包的类型和日志文件信息
	
	//以下是对该结构体的初始化
	sniffer.logfile=fopen("log.txt","w");
	if(sniffer.logfile==NULL)
	{
		perror("fopen():");
		exit(1);
	}
	fprintf(sniffer.logfile,"***LOGFILE(%s -%s)***\n",__DATE__,__TIME__);
	//t_protocol结构体中存储的是协议的类型和数据包的总数
	sniffer.prot=(t_protocol*)malloc(sizeof(t_protocol));

	//创建原始套接字
	int sd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP));//获得IPV4的数据链路层帧，即数据包含以太网帧头。14+20+(8:udp 或 20:tcp)
	if(sd<0)
	{
		perror("socket():");
		exit(2);
	}

	getstart();//打印一下提示信息
	
	//接下来就是循环侦听以太网，并处理
	fd_set fd_read;
	while(1)
	{
		FD_ZERO(&fd_read);
		FD_SET(0,&fd_read);
		FD_SET(sd,&fd_read);
		//多路复用检测sd套接字和标准输入
		int ret=select(sd+1,&fd_read,NULL,NULL,NULL);
		if(ret<0)
		{
			close(sd);
			perror("select()");
			exit(3);
		}
		else
		{
			if(FD_ISSET(0,&fd_read))//如果检测的是标准输入的情况
			{
				if(Respond(sd)==1)//这里只处理退出，重点在获取帧数据上
				{
					break;
				}
			}
			else if(FD_ISSET(sd,&fd_read))
			{
				int saddr_size=sizeof(saddr);
				int data_size=recvfrom(sd ,buffer ,65536 ,0 ,&saddr ,(socklen_t*)&saddr_size);
				//读取以太网数据帧的内容
				if(data_size<=0)//data_size为数据帧的总长度
				{
					close(sd);
					perror("recvfrom()");
					exit(4);
				}
				ProcessPacket(buffer,data_size,&sniffer);
			}
		}
	}
	close(sd);
	fclose(sniffer.logfile);
	free(sniffer.prot);
	free(buffer);
	return 0;
}

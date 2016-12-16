#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "UDPServer.h"

CUDPServer::CUDPServer()
{
}

CUDPServer::CUDPServer(int bind_port)
{
	int z = 0;
	struct sockaddr_in addr_inet;

	addr_inet.sin_family = AF_INET;
	addr_inet.sin_port = htons(bind_port);
	//addr_inet.sin_addr.s_addr = htonl(INADDR_ANY);
	addr_inet.sin_addr.s_addr = htonl(INADDR_ANY);
	bzero(&(addr_inet.sin_zero), 8);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1)
	{
		perror("socket() error, exit!");
		exit(-1);
	}

	z = bind(sockfd, (struct sockaddr*)&addr_inet, sizeof(addr_inet));
	if (z == -1)
	{
		perror("bind() error, exit!");
		exit(-1);
	}

	EU_info_upd_flag = 0;
	House_bind_upd_flag = 0;
	ISMS_policy_upd_flag = 0;
	
	pthread_create(&handle_recv, NULL, thread_recv_msg, this);
}

void *CUDPServer::thread_recv_msg(void *arg)
{
	CUDPServer *obj = (CUDPServer*)arg;
	obj->recv_notice_msg(arg);
}

void CUDPServer::recv_notice_msg(void *arg)
{
	printf("start recv_notice_msg.............\n");

	int len = 0, z = 0;
	char recv_buf[1024];
	struct sockaddr_in addr_client;
	len = sizeof(addr_client);

	while(1)
	{
		bzero(recv_buf, sizeof(recv_buf));
		int z = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&addr_client, (socklen_t*)&len);

		if (z < 0)
		{
			perror("recvfrom() error, continue");
			usleep(100);
		}

		recv_buf[z] = '\0';
		printf(">>>>>>>>>>>>>>>> recv_notice_msg: %s\n", recv_buf);

		if (!strncmp(recv_buf, "EU_common_info", strlen("EU_common_info")))
		{
			printf("this is a EU_Common_Info update notice......\n");
			EU_info_upd_flag = 1;
		}
		else if (!strncmp(recv_buf, "House_IP_Bind", strlen("House_IP_Bind")))
		{
			printf("this is a House_IP_Bind update notice......\n");
			House_bind_upd_flag = 1;
		}
		else if (!strncmp(recv_buf, "ISMS_policy_info", strlen("ISMS_policy_info")))
		{
			printf("this is a ISMS_policy_info update notice......\n");
			ISMS_policy_upd_flag = 1;
		}
		else
		{
			printf("this is an unknown type notice.......\n");
		}

	}
}

int CUDPServer::get_EU_flag()
{
	int cur_flag = EU_info_upd_flag;
	EU_info_upd_flag = 0;

	return cur_flag;
}

int CUDPServer::get_House_bind_flag()
{
	int cur_flag = House_bind_upd_flag;
	House_bind_upd_flag = 0;

	return cur_flag;
}

int CUDPServer::get_ISMS_policy_flag()
{
	int cur_flag = ISMS_policy_upd_flag;
	ISMS_policy_upd_flag = 0;

	return cur_flag;
}

char CUDPServer::send_log_to_ulayer(int to_port, unsigned char *buf, unsigned int len)
{
	int send_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (send_fd == -1)
	{
		printf("send_log_to_ulayer: socket() fail!\n");
		return -1;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(to_port);

	int sendBytes = sendto(send_fd, buf, len, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
	if (sendBytes == -1)
	{
		printf("send_log_to_ulayer: sendto() fail\n");
		close(send_fd);
		return -1;
	}

	close(send_fd);

	return 0;
}

CUDPServer::~CUDPServer()
{
	close(sockfd);
}

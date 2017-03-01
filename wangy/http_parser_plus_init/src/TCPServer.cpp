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

#include "TCPServer.h"

CTCPServer::CTCPServer()
{
}

CTCPServer::CTCPServer(int bind_port)
{
	pthread_create(&handle_recv, NULL, thread_recv_msg, this);
}

void *CTCPServer::thread_recv_msg(void *arg)
{
	CTCPServer *obj = (CTCPServer*)arg;
	obj->recv_msg(arg);
}

void CTCPServer::recv_msg(void *arg)
{
	printf("CTPCServer: start recv_msg.............\n");
}


char CTCPServer::send_msg(char *to_ip, int to_port, unsigned char *buf, unsigned int len)
{
	int sendfd = 0;
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(to_port);
	inet_aton(to_ip, &addr.sin_addr);

	sendfd = socket(AF_INET, SOCK_STREAM, 6);
	if (sendfd == -1)
	{
		printf("CTCPServer::send_msg(): socket() fail\n");
		return -1;
	}

	int c = connect(sendfd, (struct sockaddr*)&addr, sizeof(addr));
	if (c == -1)
	{
		printf("CTCPServer::send_msg(): connect(%s:%d) fail\n", to_ip, to_port);
		close(sendfd);
		return -1;
	}

	int send_len = send(sendfd, buf, len, 0);
	if (send_len < 0)
	{
		printf("CTCPServer::send_msg(): send() fail\n");
		close(sendfd);
		return -1;
	}

	printf("CTCPServer::send_msg(): send successfully\n");
	close(sendfd);

	return 0;
}

CTCPServer::~CTCPServer()
{
}

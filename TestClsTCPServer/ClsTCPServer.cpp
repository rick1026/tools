/*
 * ClsTCPServer.cpp
 *
 *  Created on: 2016年4月15日
 *      Author: zhangjl
 */

#include <netinet/in.h>
#include "ClsTCPServer.h"

ClsTCPServer::ClsTCPServer() {
	// TODO Auto-generated constructor stub
	perror("You must specify the correct argument!!!");
	exit(1);
}

ClsTCPServer::ClsTCPServer(short port, callback_process func, char flg_reserv) {
	// TODO Auto-generated constructor stub
	this->backlog = 128;
	this->flg_resv = flg_reserv;
	this->port = port;
	bzero(this->str_ip, sizeof(this->str_ip));
	this->proc_fun = func;

	create_bind_socket();
	pthread_create(&hdl_thread, NULL, thread_server, this);
}

ClsTCPServer::ClsTCPServer(char *str_ip, short port, callback_process func, char flg_reserv) {
	// TODO Auto-generated constructor stub
}

ClsTCPServer::ClsTCPServer(char *str_ip, short port, callback_process func, int backlog, char flg_reserv) {
	// TODO Auto-generated constructor stub
}

ClsTCPServer::~ClsTCPServer() {
	// TODO Auto-generated destructor stub
}

int ClsTCPServer::create_bind_socket()
{
	if ((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("ClsTCPServer::create_server, create socket error, exit!!");
		exit(1);
	}
	set_reuse_opt(listen_sock);

	struct sockaddr_in serv_addr;
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(this->port);

	if (bind(listen_sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("ClsTCPServer::create_server, bind socket error, exit!!");
		exit(1);
	}

	listen(listen_sock, backlog);

	return 0;
}

void* ClsTCPServer::thread_server(void* arg)
{
	ClsTCPServer *obj = (ClsTCPServer*)arg;
	obj->do_server_work(arg);

	return NULL;
}


void ClsTCPServer::do_server_work(void* arg)
{
	int  fds[1023], idx = 0;
	int  i = 0, maxfds = 0, fds_size = sizeof(fds) / sizeof(fds[0]);
	socklen_t client_len;
	struct sockaddr_in client_addr;
	fd_set rfdset;

	stru_client_cache client_datacache[1023];
	bzero(client_datacache, sizeof(client_datacache));

	//printf("fds_size = %d, listen_sock = %d\n", fds_size, listen_sock);
	for (i = 0; i < fds_size; i++)
	{
		fds[i] = -1;
	}

	while(1)
	{
		maxfds = listen_sock;
		FD_ZERO(&rfdset);
		FD_SET(listen_sock, &rfdset);
		maxfds = (maxfds >= listen_sock) ? maxfds : listen_sock;

		for (i = 0; i < fds_size; i++)
		{
			if (fds[i] != -1)
			{
				FD_SET(fds[i], &rfdset);
				maxfds = (maxfds >= fds[i]) ? maxfds : fds[i];
			}
		}

		struct timeval tv_out = {10, 0};
		int r = select(maxfds + 1, &rfdset, 0, 0, &tv_out);
		if ( ( (r == -1) && (errno == EINTR)) || (r == 0) )
		{
			//printf("ClsTCPServer::do_server_work, timeout or signal interrupted, continue!\n");
			continue;
		}
		else if (r == -1)
		{
			printf("ClsTCPServer::do_server_work, some error occurs when select, exit!");
			exit(1);
		}

		if (FD_ISSET(listen_sock, &rfdset))
		{
			client_len = sizeof(struct sockaddr);

			// get the first free item in fds array
			idx = get_fidx_of_value(fds, fds_size, -1);
			if(idx == -1)
			{
				printf("ClsTCPServer::do_server_work, too many client, sleep 1s and continue!!!!\n");
				sleep(1);
				continue;
			}

			fds[idx] = accept(listen_sock, (struct sockaddr*) &client_addr, &client_len);

			// init the data cache for the client
			memset(&client_datacache[idx], 0, sizeof(client_datacache[idx]));
			set_sock_recvbuf(fds[idx], 8192000);
			//printf("ClsTCPServer::do_server_work, there is a new connection, idx = %d, socket = %d\n", idx, fds[idx]);
		}

		for (i = 0; i < fds_size; i++)
		{
			if (fds[i] == -1)
				continue;

			if (FD_ISSET(fds[i], &rfdset))
			{
				//printf("ClsTCPServer::do_server_work, there are new data in socket[%d] = %d\n", i, fds[i]);
				// receive the first data, malloc buffer
				if(client_datacache[i].buf == NULL)
				{
					client_datacache[i].buf = (unsigned char*) malloc(SIZE_BUF);
					bzero(client_datacache[i].buf, SIZE_BUF);
					client_datacache[i].buf_size = SIZE_BUF;
					// The following three rows is not necessary for the bzero before.
					client_datacache[i].data_len = 0;
					client_datacache[i].free_size = SIZE_BUF;
				}

				// if the available space is too small, reallocate more space,
				// but the allocated space can not bigger than MAX_SIZE_BUF.
				if (client_datacache[i].free_size < SIZE_RECV && client_datacache[i].buf_size < MAX_SIZE_BUF)
				{
					unsigned int new_size = client_datacache[i].buf_size << 1;
					client_datacache[i].buf = (unsigned char*)realloc(client_datacache[i].buf, new_size);
					bzero(client_datacache[i].buf + client_datacache[i].data_len, new_size - client_datacache[i].data_len);
					client_datacache[i].buf_size = new_size;
					client_datacache[i].free_size = new_size - client_datacache[i].data_len;
				}

				unsigned char* recv_buf = client_datacache[i].buf + client_datacache[i].data_len;
				unsigned int   recv_buf_size = client_datacache[i].free_size;
				if (recv_buf_size <= 0)
				{
					printf("ClsTCPServer::do_server_work, socket(%d), there is no free space in recv_buf, reset the buf!\n", fds[i]);
					bzero(recv_buf, client_datacache[i].buf_size);
					recv_buf_size = client_datacache[i].buf_size;
					client_datacache[i].data_len = 0;
					client_datacache[i].free_size = client_datacache[i].buf_size;
				}

				int recv_len = recv(fds[i], recv_buf, recv_buf_size, 0);
				if (recv_len == -1 && errno == EINTR)
				{
					continue;
				}
				else if (recv_len == -1) // error occurs
				{
					printf("ClsTCPServer::do_server_work, recv from socket(%d) error, close it!\n", fds[i]);
					FD_CLR(fds[i], &rfdset);
					free(client_datacache[i].buf);
					client_datacache[i].buf = NULL;
					close(fds[i]);
					fds[i] = -1;
					continue;
				}
				else if(recv_len == 0) // the connection has been closed
				{
					printf("ClsTCPServer::do_server_work, recv from socket(%d), connection closed!\n", fds[i]);
					FD_CLR(fds[i], &rfdset);
					free(client_datacache[i].buf);
					client_datacache[i].buf = NULL;
					close(fds[i]);
					fds[i] = -1;
					continue;
				}
				else if(recv_len > 0)
				{
					unsigned int process_len = 0; // 本次接收数据后已经处理的字节数
					unsigned int this_offset = 0; // 每次调用回调函数后处理的字节数
					client_datacache[i].data_len += recv_len;
					client_datacache[i].free_size = client_datacache[i].buf_size - client_datacache[i].data_len;
					unsigned int datalen = client_datacache[i].data_len;
					unsigned char *origin_buf = client_datacache[i].buf;
					unsigned char *proc_buf = origin_buf;
					unsigned int  to_be_proc_len = datalen;

					/*
					printf("ClsTCPServer::do_server_work, recv new data from socket = %d, recv_len = %d\n", fds[i], recv_len);
					printf("ClsTCPServer::do_server_work, after recv, cache info: size = %u, datalen = %u, free = %u\n",
							client_datacache[i].buf_size, client_datacache[i].data_len, client_datacache[i].free_size);
					*/

					while (process_len <= datalen)
					{
						proc_buf = proc_buf + this_offset;
						to_be_proc_len = datalen - process_len;

						this_offset = this->proc_fun(fds[i], to_be_proc_len, proc_buf, &this_offset);

						//printf("after proc_fun, this_offset = %d\n", this_offset);
						if (this_offset == 0)
						{
							unsigned char *temp_buf = (unsigned char*)malloc(to_be_proc_len);
							memcpy(temp_buf, proc_buf, to_be_proc_len);
							bzero(client_datacache[i].buf, client_datacache[i].buf_size);
							memcpy(client_datacache[i].buf, temp_buf, to_be_proc_len);
							client_datacache[i].data_len = to_be_proc_len;
							client_datacache[i].free_size = client_datacache[i].buf_size - to_be_proc_len;
							break;
						}

						process_len += this_offset;
						//printf("process_len = %d\n", process_len);
					}
					continue;
				}
				else
				{
					;
				}
			} // end of if
		}// end of for
	}// end of while
}

int ClsTCPServer::get_fidx_of_value(int *array, int num, int value)
{
	if(array == NULL)
		return -1;

	int i = 0;
	for( i = 0; i < num; i++)
	{
		if(array[i] == value)
			return i;
	}

	return -1;
}


/*
 * ClsTCPServer.h
 *
 *  Created on: 2016年4月15日
 *      Author: zhangjl
 */

#ifndef UTOSSER_CLSTCPSERVER_H_
#define UTOSSER_CLSTCPSERVER_H_

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>


#define SIZE_RECV    65536      //16K
#define SIZE_BUF     65536<<1   //32K
#define MAX_SIZE_BUF 65536<<6   //1024K

typedef struct stru_client_data_cache{
	unsigned char  *buf; // 保存待处理的数据，动态分配
	unsigned int   buf_size; // resv_buf指向空间的容量
	unsigned int   data_len;  // resv_buf中保存数据的字节数
	unsigned int   free_size; // resv_buf中剩余的字节数
}stru_client_cache;

// the callback function to process the received message.
// There are four arguments for this function.
// ---> fd: input argument, the socket where the buf comes from
// ---> len: input argument, the byte counts of the data saved in buf
// ---> buf: input argument, the content of the data
// ---> offset: output argument, the bytes the callback fuction will process.
typedef int (*callback_process)(int fd, int len, unsigned char *buf, unsigned int *offset);

class ClsTCPServer {
public:
	ClsTCPServer();
	~ClsTCPServer();

	// 仅指定端口时，在所有地址上监听，listen队列大小默认为128
	ClsTCPServer(short port, callback_process func, char flg_reserv = 1);
	// 仅指定IP和端口时，listen队列大小默认为128
	ClsTCPServer(char *str_ip, short port, callback_process func, char flg_reserv = 1);
	// 指定监听的IP和端口,以及listen队列的容量
	ClsTCPServer(char *str_ip, short port, callback_process func, int backlog = 0, char flg_reserv = 1);

private:
	pthread_t hdl_thread;  // the handle of the thread to accept request and receive message
	int       listen_sock; // the socket of listen
	int       backlog;     // the size of listen queue
	char      str_ip[256];
	short     port;        // the server port listen on
	int       flg_resv;    // the flag if need to process tcp_attach
	callback_process proc_fun;

	int          create_bind_socket();
	static void* thread_server(void*); // the thread function to accept request and receive message
	void         do_server_work(void*); // the working function for thread thread_server.
	int          get_fidx_of_value(int *array, int num, int value);
	int          get_lidx_of_value(int *array, int num, int value);

	inline void set_reuse_opt(int listenfd){
		int opt = 1;
		setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	}

	inline void set_sock_sendbuf(int sock, int bytes){
		int sys_buf_len = bytes;
		socklen_t opt_len = sizeof(sys_buf_len);
		setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sys_buf_len, opt_len);
	}

	inline void set_sock_recvbuf(int sock, int bytes){
		int sys_buf_len = bytes;
		socklen_t opt_len = sizeof(sys_buf_len);
		setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &sys_buf_len, opt_len);
	}


};

#endif /* UTOSSER_CLSTCPSERVER_H_ */

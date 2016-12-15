#include <stdio.h>
#include "ClsTCPServer.h"

int   my_proc_func(int fd, int len, unsigned char *buf, unsigned int *offset);

int main(int argc, char **argv){
	ClsTCPServer MyServer(8000, my_proc_func);

	do{
		sleep(30);
	}while(1);

	return 0;
}

int my_proc_func(int fd, int datalen, unsigned char *buf, unsigned int *offset)
{
	if (datalen < 8)
		return 0;

	int len = 8;
	char *temp_buf = (char*)malloc(9);
	bzero(temp_buf, 9);
	memcpy(temp_buf, buf, len);

	printf("process_msg_from socket(%d) = %s\n", fd, temp_buf);

	printf("there are %d bytes have been processed this time!\n", len);

	return len;
}


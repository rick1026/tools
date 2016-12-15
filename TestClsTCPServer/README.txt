This is a class of a tcp server, which is named ClsTCPServer.
You can create a object of the class, which is equals to create
a tcp server. When you did this, you should specified two arguments:
(1) port: the server will listen on the specified port.
(2) callback_function: the function to process the received data 
            from a client of the server.

The callback function is defined as follows:

-----------------------------------------------------------------------
int callback(int fd, int len, unsigned char *buf, unsigned int *offset);

fd: the client socket where the data to be processed comes from.
len: the length of the data to be processed.
buf: the content of the data to be processed.
offset: output argument, the length of the processed data in the function.
return value: the length of the processed data in the function.

If you expect to receive a 10 bytes data, but the passed data pointed by 
argument buf is only 8 bytes, you should set the offset as zero and return
zero in the callback function. Then the object will cache the 8 bytes data
and merge it with the next coming data from the client and call the callback
function again. If there are 5 bytes coming next time, the the len is 8+5=13,
and buf content is "old 8 bytes new 5 bytes" when the callback function is 
called.

This is a sample example to use the class. The specified callback expect to 
receive a 8-bytes string and print it to the stdout, then return.




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

	*offset = len;

	return len;
}


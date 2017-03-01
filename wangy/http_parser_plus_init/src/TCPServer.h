class CTCPServer
{
public:
	CTCPServer();
	CTCPServer(int bind_port);
	~CTCPServer();

	char send_msg(char *to_ip, int to_port, unsigned char *buf, unsigned int len);
	
private:
	static void* thread_recv_msg(void*);
	void recv_msg(void*);

public:

private:
	//int         sockfd;
	pthread_t   handle_recv;
};

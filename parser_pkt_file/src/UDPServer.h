#ifndef __UDPSERVER_H
#define __UDPSERVER_H

#define UC_MSG_TYPE_ISMS_POLICY    0x02
#define UC_MSG_TYPE_HOUSE_INFO     0x03      

class CUDPServer
{
public:
	CUDPServer();
	CUDPServer(int bind_port);
	~CUDPServer();

	int get_EU_flag();
	int get_House_bind_flag();
	int get_ISMS_policy_flag();

	char send_log_to_ulayer(int to_port, unsigned char *buf, unsigned int len);
	
private:
	static void* thread_recv_msg(void*);
	void recv_notice_msg(void*);

public:

private:
	int         sockfd;
	pthread_t   handle_recv;

	int         EU_info_upd_flag;
	int         House_bind_upd_flag;
	int         ISMS_policy_upd_flag;
};


#endif

// end of the file


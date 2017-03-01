/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
#ifndef __PKT_PROCESSOR_H
#define __PKT_PROCESSOR_H

#include <pcap.h>
#include <string>
#include <vector>
#include <map>

using namespace std;


#include "data_def.h"
#include "mwm.h"
#include "http_url_cache.h"
#include "conn_hash_cache.h"
#include "http_reassemble.h"
#include "UDPServer.h"
#include "TCPServer.h"
#include "db_operate.h"
#include "BitMap.h"

typedef struct __stru_match_result
{
	unsigned int   bingo_policy;
	unsigned int   bingo_cache;
}stru_match_rslt;
typedef map<string, stru_match_rslt>  MapMatchRslt;

typedef struct
{
int rule_id;
int key_id;
char keyword[256];
}stru_result_info;

class cls_pkt_processor
{
private:

    int        client_id;
	time_t cur_time;
	time_t last_time;
 vector<stru_result_info>            result_info_list;
 vector<stru_ud_log> *send_buf;
 vector<stru_ud_log> *send_buf_last;
vector<stru_ud_log>	*send_buf_a;
vector<stru_ud_log>	*send_buf_b;
sem_t send_buf_sem;
sem_t conn_hash_sem;
unsigned int send_buf_index;
 unsigned long long delt1;
 unsigned long long delt2;
 unsigned long long delt3;
 unsigned long long delt4;
 unsigned long long delt5;
 unsigned long long delt6;
 unsigned long long delt7;
 unsigned long long delt8;
 unsigned long long delt9;
 unsigned long long delt10;
 unsigned long long delt11;
 unsigned long long delt12;
 
 struct ud_header ud_head;
 unsigned char command_house[32];
 unsigned char command_house_len;
 int         http_num;
 int         tcp_num;
    CUDPServer *udp_comm;
    CTCPServer *tcp_comm;

    int serv_port_policy_update;
    int client_port_ud_log;
    int client_port_ud_attach;

	hash_table        *conn_hash;
    cls_tcp_reassemble   ClsTCPReassemble;
    cls_http_reassemble  ClsHTTPReassemble;
    cls_conn_hash_cache  ClsCONNHashCache;
    cls_http_url_cache   ClsHTTPUrlCache;
    cls_db_operation     ClsDBOperation;

    unsigned int         bingo_cnt;
    MWM_STRUCT           *mwm_handle;
    int                  mwm_search_rule_num;
    struContWarnRule     *(ptr_content_rule)[MAX_RULE_NUM_MWM_SEARCH];

	char                 house_id[256];
	char                 house_ip[32];

    ////// socket to send reset packet
    int                  sock_reset;

    ////// all the effective policies
    vector<stru_ISMS_policy> vector_policy;
    MapHostRuleInfo          map_site_rule;
    MapUrlRuleInfo           map_url_rule;
    MapProtoRuleInfo         map_proto_rule;
    MapIPRuleInfo            map_sip_rule;
    MapIPRuleInfo            map_dip_rule;
    MapPortRuleInfo          map_sport_rule;
    MapPortRuleInfo          map_dport_rule;

	unsigned long            ISMS_ply_upd_time;

    
public:
  cls_pkt_processor();
  cls_pkt_processor(int client_id);
  ~cls_pkt_processor();

  void packet_processer(unsigned char *arg, const struct pcap_pkthdr *ph, const unsigned char *packet);
  int DoTCPPacketProcess(const LLHeadStru *pStruLLHead,
                         const L3HeadStru *pStruL3Head,
                         const TCPHeadStru *pStruTCPHead,
                         unsigned int sip,
                         unsigned short sport,
                         unsigned int dip,
                         unsigned short dport,
                         const unsigned char *pContent,
                         const unsigned int content_len);
private:
	void Initialize();
	char do_action_by_action(ENUM_PKT_ACTION action,
		                     const L3HeadStru *pStruL3Head,
                             const TCPHeadStru *pStruTCPHead, 
                             int              proto,
                             unsigned long    sip,
                             unsigned long    dip,
                             unsigned int     sport,
                             unsigned int     dport, 
                             unsigned char    *host);

    char do_action_by_policy(stru_ISMS_policy policy,
                             const L3HeadStru *pStruL3Head,
                             const TCPHeadStru *pStruTCPHead,
                             int               proto,
                             unsigned long     sip,
                             unsigned long     dip,
                             unsigned int      sport,
                             unsigned int      dport,
                             char     *host,
							char *url,
							char *keyword);

unsigned char* get_send_data(stru_ud_log ud_log);
    void send_L3_reset(int sock,
                       unsigned long sip,
                       unsigned long dip,
                       unsigned int  sport,
                       unsigned int  dport,
                       unsigned long seq,
                       unsigned long next_ack_seq);
    unsigned short in_cksum(unsigned short *addr, int len);

	static void* radom_work_func(void*);
    void do_radom_work(void*);
    static void* send_msg_thread_work(void*);
	void send_msg_thread(void *arg);

	ListRuleInfo do_keyword_match(const LLHeadStru *pStruLLHead,
		const L3HeadStru *pStruL3Head,
		//const L4HeadUnion *pUnionL4Head,
		const TCPHeadStru *pStruTCPHead,
		unsigned int sip,
		unsigned short sport,
		unsigned int dip,
		unsigned short dport,
		unsigned char *data_buf,
		unsigned int data_len);

    inline void add_rule_to_map(stru_prule_position, stru_ISMS_policy_rule);
	inline void clear_conn_hash ();

    char read_house_info();
    char read_rules_info();
    char read_comm_conf_from_file();
    char load_ISMS_policies();
    
	char assemble_monitor_log_packet();
	char assemble_filter_log_packet();
    //int  assemble_monitor_log_packet(unsigned int sip,unsigned int dip, unsigned short sport,unsigned short dport,char *host, char *url, char *keyword,unsigned char **out_buf);
int assemble_log_packet (char type,unsigned int sip,unsigned int dip,
    unsigned short sport,unsigned short dport,
    char *host,char *url,
    char *keyword,
    stru_ud_log *ud_log_info_for_monitor);
    int  assemble_filter_log_packet(unsigned char **out_buf);


private:
	// for debug
	MapMatchRslt       map_result;
	void               update_map_rslt_info(char *host, char *url, int type);

private:
	unsigned long      cap_pkt_cnt;

	unsigned long      num_tcp_conn;
	unsigned long      num_http_req_pkt_recv;
	unsigned long      num_http_resp_pkt_recv;
	unsigned long      num_http_req_sdu_data;
	unsigned long      num_http_resp_sdu_data;
	unsigned long      num_http_req_data;
	unsigned long      num_http_resp_data;
	unsigned long      num_http_other_data;
};

#endif


// end of the file

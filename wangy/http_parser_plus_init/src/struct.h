#ifndef __STRUCT_H
#define __STRUCT_H

#include <stdint.h>
#include <semaphore.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include "conn_hash_cache.h"
#include "beap_hash.h"
#include "BitMap.h"
typedef struct{
    unsigned char   proto;
    unsigned int    src_ip;
    unsigned int    dst_ip;
    unsigned short    src_port;
    unsigned short    dst_port;
}TCPsessionID;
    enum TCPsessionState{
         null = 0,
          LISTEN = 1,
          SYN_SENT = 2,
          SYN_RECVD = 3,
          SYN_SIM = 4,
          ESTAB = 5,
          FIN_WAIT_1 = 6,
          FIN_WAIT_2 = 7,
          LAST_ACK = 8,
          CLOSING = 9,
          TIME_WAIT = 10
     };
typedef struct TCPSduCbStru TCPSduCb;
struct TCPSduCbStru{
    unsigned int    start_seq;
    unsigned int    end_seq;
    unsigned char          data_buf[1600];
    unsigned int    data_len;

    char          PUSH_flaged;

    TCPSduCb        *prev_cb;
    TCPSduCb        *next_cb;
};

typedef struct{
//    TCPsessionID            id;
    TCPsessionID            report_id;
    enum TCPsessionState    state;
    unsigned int            init_forward_seq; // the seq of the first SYN packet of a tcp connection, belongs the sender
    unsigned int            init_backward_seq; // the seq of the first SYN_ACK packet of a tcp connection, belongs the receiver
    unsigned int            forward_min_seq;
    unsigned char           forward_min_got;
    unsigned int            backward_min_seq;
    unsigned char           backward_min_got;

    TCPSduCb                *forward_sdu_cb_head;
    TCPSduCb                *forward_sdu_cb_tail;
    TCPSduCb                *backward_sdu_cb_head;
    TCPSduCb                *backward_sdu_cb_tail;

    unsigned int            fin_sender;
    unsigned int            forward_packet_num;
    unsigned int            backward_packet_num;
    unsigned int            forward_push_num;
    unsigned int            backward_push_num;
    unsigned int            forward_bytes;
    unsigned int            backward_bytes;
    long                    time_stamp;
    //char                  scan_state;
    unsigned int            sender_ip;
}TCPsession;


typedef enum PKT_ACTION{
    PKT_RET = 0,
    PKT_RST = 1,
    PKT_DEAL = 2
}ENUM_PKT_ACTION;
 typedef map < int, ClsBMap > MapPlyBMap;

// save an connection an the action to the packets of the connection
typedef struct stru_cache_conn_node{
//TCPsessionID      sess_id;
char              url[256];
char              host[256];

ENUM_PKT_ACTION   action;
int               verdict_flag;
MapPlyBMap        ply_BMap; // key is policy_index, content is the BMap of every policy
unsigned long     do_match_time;
}stru_conn_node;
typedef enum ENUM_HTTP_STATUS{
    S_DFFAULT = 0,
    S_REQ_HEAD_START = 1,
    S_REQ_HEAD_END = 2,
    S_REQ_END = 3,
    S_RSP_HEAD_START = 4,
    S_RSP_HEAD_END = 5,
    S_RSP_END = 6
}HTTP_STATUS;

typedef struct _stru_tcp_sdu_node{
    unsigned char                 *data;
    unsigned int                  data_len;
    struct _stru_tcp_sdu_node     *next;
}stru_tcpsdu_node;
typedef struct _http_header
{
  int method;                   // unknown(0), get(1), post(2), resp(3)
  int content_type;             // text == 1
  char url[256];
  char sufix_url[8];
  char host[256];
  int content_length;
  int chunk_flag;
  int gzip_flag;
  int max_age;
  int cache_flag;
  unsigned long expire_tm;
} stru_http_header;

typedef struct __stru_policy_rule_position
{
  int ply_idx;                  // the index of the policy
  int rule_idx;                 // the index of the rule in the policy
} stru_prule_position;

typedef list < stru_prule_position > ListRuleInfo;

typedef struct _stru_ISMS_policy
{
  unsigned long MsgNo;
  char CmdID[64];
  int Type;
  int RuleNum;
  int BlockFlag;
  int LogFlag;
  int Level;
  unsigned long EffectTime;
  unsigned long ExpireTime;
  unsigned long MsgSerialNo;
  int BindStatus;
  char BindHouseID[256];
    vector < struct stru_ISMS_policy_rule >vector_rule;
  unsigned long UpdateTime;
  ClsBMap BMap;
  char *keyword_first;
} stru_ISMS_policy;

typedef struct _stru_http_info{
 //   TCPsessionID      sessid;
    HTTP_STATUS       status;
    char              url[256];
    char              host[256];
    int               method;
    int               req_body_len;
    int               req_head_len;
    int               req_got_len;
    int               rsp_body_len;
    int               rsp_head_len;
    int               rsp_got_len;
    char              content_type[64];
	int               type_text_flag;
    char              rsp_chunk_flag;
    char              rsp_gzip_flag;
    //unsigned long     rsp_gzip_cksum;
    char              rsp_gzip_cksum[8];
    unsigned int      seq_no;
    stru_tcpsdu_node  *sdu_list_up;
    stru_tcpsdu_node  *sdu_list_down;
}stru_http_info;



typedef struct
{
  time_t time_stamp;
  TCPsessionID sess_id;
  stru_conn_node *conn_node;
  TCPsession *tcp_node;
  stru_http_info *http_node;
} stru_hash_node;

typedef struct
{
    unsigned short  source_port;
    unsigned short  dest_port;
    unsigned int    seq_num;
    unsigned int    ack_num;
    unsigned char  header_len;
    unsigned char  flags;
    unsigned short  win_size;
    unsigned short  checksum;
    //unsigned char options[12];
    unsigned short  urg;
}TCPHeadStru;
#define SIZE_TCP_HEAD sizeof(TCPHeadStru)
#endif

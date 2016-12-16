#ifndef __DATA_DEF_H
#define __DATA_DEF_H

#include <stdint.h>
#include <string>
#include <list>
#include <vector>
#include <map>

using namespace std;

#include "linux_list.h"

// the following variables is definied for mwm search
#define MAXN 0x10001 
#define MAXM 1001

#define MAX_RULE_NUM_MWM_SEARCH  65536 
#define MAX_KEY_NUM_PER_RULE    128
#define SIZE_SEARCH_RSLT   (MAX_RULE_NUM_MWM_SEARCH*MAX_KEY_NUM_PER_RULE/8) 
#define SIZE_PER_RULE_RSLT   (MAX_KEY_NUM_PER_RULE>>3) 
#define KEY_NUM_PER_RULE_RSLT   (sizeof(unsigned char)<<3) 

#define MAX_KEY_LEN             128     
#define MIN_KEY_LEN             4       



// type of the policy received from CU
#define POLICY_HOST_WHITE       5
#define POLICY_HOST_BLACK       6
#define POLICY_MONITOR          1
#define POLICY_FILTER           2

// 
#define MAX_RULE_PER_POLICY     MAX_KEY_NUM_PER_RULE
#define MAX_POLICY_NUM          16





typedef struct __struCapIntf
{
	struct list_head	ptr;
	char      	     	intf_name[16];
}struCapIntf;




#define ICMP_PROTO 0x01
#define IP_PROTO    0x0800
#define UDP_PROTO 0x11
#define TCP_PROTO   0x06

#pragma pack(1)

typedef struct
{
    unsigned char dest_address[6];
    unsigned char source_address[6];
    unsigned short  protocol;
    unsigned short  vlan_id;
}LLHeadStru;
#define SIZE_LL_HEAD       sizeof(LLHeadStru)
#define SIZE_BASE_LL_HEAD  14
#define SIZE_VLAN_LL_HEAD  (SIZE_BASE_LL_HEAD+4)

typedef struct
{
    unsigned char  version;
    unsigned char  diff_serv_field;
    unsigned short  total_len;
    unsigned short  identification;
    unsigned char  flag;
    unsigned char  frag_offset2;
    unsigned char  TTL;
    unsigned char  protocol;
    unsigned short  header_checksum;
    unsigned int   source_addr;
    unsigned int   dest_addr;
}L3HeadStru;


typedef struct
{
    unsigned short  source_port;
    unsigned short  dest_port;
    unsigned short  len;
    unsigned short  check_sum;
}UDPHeadStru;
#define SIZE_UDP_HEAD sizeof(UDPHeadStru)

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


typedef union{
    UDPHeadStru UDPHead;
    TCPHeadStru TCPHead;
}L4HeadUnion;

struct pseudo_IP_header
{
    unsigned long      source, destination;
    char               zero_byte, protocol;
    unsigned short     TCP_UDP_len;
};


#pragma pack()

#endif

// end of the file

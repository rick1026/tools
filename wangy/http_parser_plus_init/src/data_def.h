#ifndef __DATA_DEF_H
#define __DATA_DEF_H

#include <stdint.h>
#include <string>
#include <list>
#include <vector>
#include <map>

using namespace std;

#include "linux_list.h"
#include "tcp_reassemble.h"
#include "BitMap.h"

// the following variables is definied for mwm search
#define MAXN 0x10001
#define MAXM 1001

#define MAX_RULE_NUM_MWM_SEARCH  1024
#define MAX_KEY_NUM_PER_RULE    128
#define SIZE_SEARCH_RSLT 16384
//#define SIZE_SEARCH_RSLT   (MAX_RULE_NUM_MWM_SEARCH*MAX_KEY_NUM_PER_RULE/8)
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

// the coordinate of a rule in the policy_vector
typedef map < string, ListRuleInfo > MapHostRuleInfo;
typedef map < string, ListRuleInfo > MapUrlRuleInfo;
typedef map < int, ListRuleInfo > MapProtoRuleInfo;
typedef map < unsigned long, ListRuleInfo > MapIPRuleInfo;
typedef map < unsigned int, ListRuleInfo > MapPortRuleInfo;
typedef map < int, ClsBMap > MapPolicyBMap;




typedef struct __struCapIntf
{
  struct list_head ptr;
  char intf_name[16];
} struCapIntf;


#define ICMP_PROTO 0x01
#define IP_PROTO    0x0800
#define UDP_PROTO 0x11
#define TCP_PROTO   0x06

typedef struct
{
  unsigned char dest_address[6];
  unsigned char source_address[6];
  unsigned short protocol;
  unsigned short vlan_id;
} LLHeadStru;
#define SIZE_LL_HEAD       sizeof(LLHeadStru)
#define SIZE_BASE_LL_HEAD  14
#define SIZE_VLAN_LL_HEAD  (SIZE_BASE_LL_HEAD+4)

typedef struct
{
  unsigned char version;
  unsigned char diff_serv_field;
  unsigned short total_len;
  unsigned short identification;
  unsigned char flag;
  unsigned char frag_offset2;
  unsigned char TTL;
  unsigned char protocol;
  unsigned short header_checksum;
  unsigned int source_addr;
  unsigned int dest_addr;
} L3HeadStru;


typedef struct
{
  unsigned short source_port;
  unsigned short dest_port;
  unsigned short len;
  unsigned short check_sum;
} UDPHeadStru;
#define SIZE_UDP_HEAD sizeof(UDPHeadStru)

// typedef struct
// {
//     unsigned short  source_port;
//     unsigned short  dest_port;
//     unsigned long  seq_num;
//     unsigned long  ack_num;
//     unsigned char  header_len;
//     unsigned char  flags;
//     unsigned short  win_size;
//     unsigned short  checksum;
//     //unsigned char options[12];
//     unsigned short  urg;
// }TCPHeadStru;


typedef union
{
  UDPHeadStru UDPHead;
  TCPHeadStru TCPHead;
} L4HeadUnion;

struct pseudo_IP_header
{
  unsigned long source, destination;
  char zero_byte, protocol;
  unsigned short TCP_UDP_len;
};


typedef struct __struMwmSearchKey
{
  char content[MAX_KEY_LEN];	// the key's content 
  int index;			// the index of the key in the rule, from 0 to 
  int id;			// the seqno of a key in its belonging rule
  int len;			// the byte numbers of he key
} struMwmSearchKey;

typedef struct __struContWarnRule
{
  unsigned int rule_id;		// id of a rule
  int key_num;			// the number of keywords contained in a rule
  struMwmSearchKey *ptr_key[MAX_KEY_NUM_PER_RULE];	// pointer to the content of every key
} struContWarnRule;




struct ud_header
{
  unsigned char Ver_and_Resv;
  unsigned char Proto_Signature[3];
  unsigned char DevID;
  unsigned char DeviceSerialNo[3];
  unsigned char Packet_Type;
  unsigned char Packet_Subtype;
  unsigned char Resv[2];
  unsigned int Packet_Length;	// 包不包括头部长度的的兜娜，

};

struct monitor_attach_content
{
  unsigned short AttachmentfileName_Length;
  unsigned char *AttachmentfileName;
};

typedef struct monitor_log
{
  char type;
  unsigned char SourceIP_Length;
  unsigned char *SrcIp;
  unsigned char DestinationIP_Length;
  unsigned char *DestIp;
  unsigned short SrcPort;
  unsigned short DestPort;
  unsigned char *DomainName;
  unsigned char *Title;
  unsigned char *Content;
  unsigned char *Url;
  unsigned char Attachmentfile_Num;
  struct monitor_attach_content *attach_content_t;
  unsigned int GatherTime;
  unsigned char *keyword;

}stru_ud_log;


#if 0
struct monitor_log_info
{
  unsigned char CommandID[10];
  unsigned char House_ID_Length;
  unsigned char *House_ID;
  unsigned char SourceIP_Length;
  unsigned char *SrcIp;
  unsigned char DestinationIP_Length;
  unsigned char *DestIp;
  unsigned short SrcPort;
  unsigned short DestPort;
  unsigned short DomainName_Length;
  unsigned char *DomainName;
  unsigned short ProxyType_Flag;
  unsigned short ProxyType;
  unsigned char ProxyIp_Length;
  unsigned char *ProxyIp;
  unsigned short ProxyPort;
  unsigned short Title_Length;
  unsigned char *Title;
  unsigned int Content_Length;
  unsigned char *Content;
  unsigned short Url_Length;
  unsigned char *Url;
  unsigned char Attachmentfile_Num;
  struct monitor_attach_content *attach_content_t;
  unsigned int GatherTime;
};
#endif


struct stru_ISMS_policy_rule;


struct stru_ISMS_policy_rule
{
  int policy_index;
  int Rule_SubType;
  char Rule_Host[256];
  char Rule_Url[256];
  int Rule_ProtoL4;
  unsigned long Rule_SipStart;
  unsigned long Rule_SipEnd;
  unsigned long Rule_DipStart;
  unsigned long Rule_DipEnd;
  unsigned int Rule_SportStart;
  unsigned int Rule_SportEnd;
  unsigned int Rule_DportStart;
  unsigned int Rule_DportEnd;
  unsigned char Rule_Keyword[256];
  int Rule_KeyRange;		// bit value
};


#endif

// end of the file

/*
 * extern_struct_def.h
 *
 *  Created on: 2016-1-26
 *      Author: wy
 *      this file is for all of acs_plugin_XXX
 */

#ifndef EXTERN_STRUCT_DEF_H_
#define EXTERN_STRUCT_DEF_H_

enum {
	QQ_NETID=1030001,
	WANGWANG_NETID=1030022,
	WECHAT_NETID=1030036,
	MOMO_NETID=1030044,
	LAIWANG_NITID=1030048,
	JINGDONG_NETID=1220001,
	DANGDANG_NETID=1220002,
	TAOBAO_NETID=1220003,
	JUMEI_NETID=1220004,
	YIHAODIAN_NETID=1220005
};


typedef struct
{
	unsigned char dest_address[6];
	unsigned char source_address[6];
	unsigned short protocol;
	unsigned short vlan_id;
} LLHeadStru;

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
typedef struct
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int seq_num;
	unsigned int ack_num;
	unsigned char header_len;
	unsigned char flags;
	unsigned short win_size;
	unsigned short checksum;
	//unsigned char options[12];
	unsigned short urg; // added when merging from 3473 to 3474 on 20111116
} TCPHeadStru;
typedef union
{
	UDPHeadStru UDPHead;
	TCPHeadStru TCPHead;
} L4HeadUnion;


typedef enum
{
	http_request = 1,
	http_response = 2
} enum_http_type;

typedef struct
{
	enum_http_type http_type;
	unsigned int http_cont_length;
	unsigned char *http_version;
	unsigned char *http_method;
	unsigned char *http_host;
	unsigned char *http_uri;
	unsigned char *http_user_agent;
	unsigned char *http_reference;
	unsigned char *http_cont_encoding;
	unsigned char *http_tran_encoding;
	unsigned char *http_cont_type;
	unsigned char *http_cookies;
	unsigned char *body_start;
} HttpHeadStru;


#endif /* EXTERN_STRUCT_DEF_H_ */

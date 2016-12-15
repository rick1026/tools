/***************************************************************************
 *  MTB -- MultiThread Booster Engine for Wisetone QZT                      *
 *         by Brian He   Sep 2011                                           *
 ***************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "pkt_capture_extern.h"
#include "pkt_capture_execute.h"

#define SIZE_BASE_LL_HEAD 14
#define SIZE_VLAN_LL_HEAD  SIZE_BASE_LL_HEAD+4
#define VLAN_PROTO  0x8100
#define IP_PROTO        0x0800
#define PPPOE_PROTO  0x8864
#define TCP_PROTO       0x06
#define UDP_PROTO 0x11
#define SIZE_PPPOE_LL_HEAD  22

#define SIZE_LL_HEAD    sizeof(LLHeadStru)
#define SIZE_L3_HEAD    sizeof(L3HeadStru)
#define SIZE_UDP_HEAD   sizeof(UDPHeadStru)

#define SIZE_TCP_HEAD   sizeof(TCPHeadStru)

enum UseTypeEnum
{
	use_lan = 0, use_wan = 1
};

int acs_write_packet_to_file(char *file_name, char*data, int cap_len, int data_len)
{
	typedef struct __file_header
	{
		unsigned int iMagic;
		unsigned short iMaVersion;
		unsigned short iMiVersion;
		unsigned int iTimezone;
		unsigned int iSigFlags;
		unsigned int iSnapLen;
		unsigned int iLinkType;
	} file_header;

	typedef struct __pkthdr
	{
		unsigned int iTimeSecond;
		unsigned int iTimeSS;
		unsigned int iPLength;
		unsigned int iLength;
	} pkthdr;
	FILE *fp = fopen(file_name, "a+");
	struct stat f_stat;
	file_header fileHdr;
	unsigned char buf[128];
	memset(buf, 0, sizeof(buf));
	pkthdr packHdr;
	stat(file_name, &f_stat);
	if (f_stat.st_size == 0)
	{
		memset(&fileHdr, 0, sizeof(fileHdr));
		fileHdr.iMagic = 0xa1b2c3d4;
		fileHdr.iMaVersion = 0x2;
		fileHdr.iMiVersion = 0x4;
		fileHdr.iTimezone = 0x0;
		fileHdr.iSigFlags = 0x0;
		fileHdr.iSnapLen = 0xffff;
		fileHdr.iLinkType = 0x1;
		fwrite(&fileHdr, sizeof(fileHdr), 1, fp);
	}
	memset(&packHdr, 0, sizeof(packHdr));
	packHdr.iTimeSecond = time(NULL);
	packHdr.iTimeSS = 0;
	packHdr.iPLength = cap_len;
	packHdr.iLength = data_len;
	fwrite(&packHdr, sizeof(packHdr), 1, fp);
	fwrite(data, 1, data_len, fp);
	fclose(fp);
	return 0;
}

char GetPAPAccount(const unsigned char *pPacket, LLHeadStru *struLLHead, unsigned short sessionId)
{
	unsigned char accout_len = 0;
	unsigned char passwd_len = 0;
	char account[128];
	char passwd[128];
	bzero(account, sizeof(account));
	bzero(passwd, sizeof(passwd));
	if (*pPacket == 0x01)
	{
		accout_len = *(char*) (pPacket + 4);
		memcpy(account, pPacket + 5, accout_len);
		passwd_len = *(char*) (pPacket + 4 + 1 + accout_len);
		memcpy(passwd, pPacket + 5 + accout_len + 1, passwd_len);
		printf("Get PPP 帐号:%s,密码:%s,sessId = 0x%x(%d)\n", account, passwd, sessionId, sessionId);
	}
	struLLHead->protocol = 0;
	return BEAP_SUCCESS;
}

char GetCHAPAccount(const unsigned char *pPacket, LLHeadStru *struLLHead, unsigned short sessionId)
{
	unsigned char accout_len = 0;
	unsigned char passwd_len = 0;
	char account[128];
	char passwd[128];
	bzero(account, sizeof(account));
	bzero(passwd, sizeof(passwd));
	if (*pPacket == 0x02)
	{
		accout_len = ntohs(*(short*) (pPacket + 2)) - 4 - (*(char*) (pPacket + 4)) - 1;
		passwd_len = *(char*) (pPacket + 4);
		memcpy(account, pPacket + 5 + passwd_len, accout_len);
		memcpy(passwd, pPacket + 5, passwd_len);
	}
	struLLHead->protocol = 0;
	return BEAP_SUCCESS;
}

char GetPPPIp(const unsigned char *pPacket, LLHeadStru *struLLHead, unsigned int *ip)
{
	if (*pPacket == 0x03)
	{
		*ip = ntohl(*(unsigned int *) (pPacket + 6));
	}
	struLLHead->protocol = 0;

	return BEAP_SUCCESS;
}

char ProcessVlan(const unsigned char *pPacket, LLHeadStru *struLLHead)
{
	struLLHead->vlan_id = ntohs(struLLHead->vlan_id);
	struLLHead->vlan_id &= 0x4fff;
	struLLHead->protocol = ntohs(*(unsigned short*) (pPacket + 2));
	return BEAP_SUCCESS;
}

char ProcessPPPoe(const unsigned char *pPacket, LLHeadStru *struLLHead, unsigned short *pppSessId)
{
	struLLHead->vlan_id = -1;
	*pppSessId = ntohs(*(unsigned short *) (pPacket + 2));
	struLLHead->protocol = ntohs(*(unsigned short *) (pPacket + 6));
	return BEAP_SUCCESS;
}

char ProcessLLHead(unsigned char *pPacket, int iCapLen, LLHeadStru *struLLHead, int *iHeadLen)
{
	unsigned short pppSessId = 0;
	unsigned int ip = 0;
	if (iCapLen < sizeof(LLHeadStru)) return BEAP_FAIL;
	memcpy(struLLHead, pPacket, sizeof(LLHeadStru));
	struLLHead->protocol = ntohs(struLLHead->protocol);
	pPacket += 14;
	*iHeadLen = 14;

	do
	{
		if (struLLHead->protocol == IP_PROTO)
		{
			struLLHead->vlan_id = -1;
			return BEAP_SUCCESS;
		}
		else if (struLLHead->protocol == VLAN_PROTO || struLLHead->protocol == 0x9100)
		{
			ProcessVlan(pPacket, struLLHead);
			pPacket += 4;
			*iHeadLen += 4;
		}
		else if (struLLHead->protocol == PPPOE_PROTO)
		{
			if (iCapLen < *iHeadLen + 8) break;
			ProcessPPPoe(pPacket, struLLHead, &pppSessId);
			*iHeadLen += 8;
			pPacket += 8;
		}
		else if (struLLHead->protocol == 0xC023) //PAP
		{
			if (iCapLen < 44) break;
			GetPAPAccount(pPacket, struLLHead, pppSessId);
			break;
		}
		else if (struLLHead->protocol == 0xC223) //CHAP
		{
			if (iCapLen < 44) break;
			GetCHAPAccount(pPacket, struLLHead, pppSessId);
			break;
		}
		else if (struLLHead->protocol == 0x8021) //PPP ctrl
		{
			if (iCapLen < 44) break;
			GetPPPIp(pPacket, struLLHead, &ip);
			break;
		}
		else if (struLLHead->protocol == 0x0021) //IPV4
		{
			//PPPModeSessinChange(struLLHead,pppSessId);
			struLLHead->vlan_id = -1;
			return BEAP_SUCCESS;
		}
		else
		{
			break;
		}
		if (*iHeadLen >= iCapLen)
		{
			return BEAP_FAIL;
		}
	}
	while (struLLHead->protocol);
	return BEAP_FAIL;
}

char ProcessIpHead(const unsigned char *pPacket, int iCapLen, L3HeadStru *struL3Head, int *iHeadLen)
{
	int iplen = 0;

	memcpy(struL3Head, pPacket, sizeof(L3HeadStru));
	struL3Head->source_addr = ntohl(struL3Head->source_addr);
	struL3Head->dest_addr = ntohl(struL3Head->dest_addr);
	struL3Head->total_len = ntohs(struL3Head->total_len);
	*iHeadLen = (struL3Head->version & 0x0f) * 4;
	if (struL3Head->total_len > iCapLen)
	{
		return BEAP_FAIL;
	}
	return BEAP_SUCCESS;
}
char ProcessTcpHead(const unsigned char *pPacket, int iCapLen, TCPHeadStru *struTCPHead, int *iTcpLen)
{
	int iplen = 0;
	int iHeadLen = 0;
	unsigned int tcp_head_len = 0;
	memcpy(struTCPHead, pPacket, sizeof(TCPHeadStru));
	struTCPHead->source_port = ntohs(struTCPHead->source_port);
	struTCPHead->dest_port = ntohs(struTCPHead->dest_port);
	struTCPHead->seq_num = ntohl(struTCPHead->seq_num);
	struTCPHead->ack_num = ntohl(struTCPHead->ack_num);

	*iTcpLen = ((struTCPHead->header_len & 0xf0) >> 4) * 4;

	return BEAP_SUCCESS;
}
char ProcessUdpHead(const unsigned char *pPacket, int iCapLen, UDPHeadStru *struUDPHead, int *iHeadLen)
{
	memcpy(struUDPHead, pPacket, sizeof(UDPHeadStru));
	struUDPHead->source_port = ntohs(struUDPHead->source_port);
	struUDPHead->dest_port = ntohs(struUDPHead->dest_port);
	*iHeadLen = SIZE_UDP_HEAD;
	return BEAP_SUCCESS;
}

char AnalysisPacket(const unsigned char *pPacket, int iCapLen, LLHeadStru *struLLHead, L3HeadStru *struL3Head, L4HeadUnion *unionL4Head, unsigned char **content, int *content_len)
{
	int ll_head_len = 0, ip_head_len = 0, ipTotalLen = 0, l4_head_len = 0, ret = 0;
	UDPHeadStru struUDPHead;
	TCPHeadStru struTCPHead;

	ret = ProcessLLHead((unsigned char *) pPacket, iCapLen, struLLHead, &ll_head_len);
	if (ret == BEAP_FAIL || iCapLen < ll_head_len)
	{
		return BEAP_FAIL;
	}

	ret = ProcessIpHead(pPacket + ll_head_len, iCapLen, struL3Head, &ip_head_len);
	if (ret == BEAP_FAIL || iCapLen < ll_head_len + ip_head_len)
	{
		return BEAP_FAIL;
	}

	ipTotalLen = struL3Head->total_len;
	if (struL3Head->protocol == TCP_PROTO)
	{
		ProcessTcpHead(pPacket + ll_head_len + ip_head_len, iCapLen, &struTCPHead, &l4_head_len);
		unionL4Head->TCPHead = struTCPHead;
	}
	else if (struL3Head->protocol == UDP_PROTO)
	{
		ProcessUdpHead(pPacket + ll_head_len + ip_head_len, iCapLen, &struUDPHead, &l4_head_len);
		unionL4Head->UDPHead = struUDPHead;
	}
	else
	{
		memset(unionL4Head, 0, sizeof(L4HeadUnion));
		*content = (unsigned char *) (pPacket + ll_head_len + ip_head_len);
		*content_len = ipTotalLen - ip_head_len;
		return BEAP_SUCCESS;
	}
	if ((l4_head_len + ip_head_len) > ipTotalLen)
	{
		return BEAP_FAIL;
	}
	*content_len = ipTotalLen - ip_head_len - l4_head_len;
	if (*content_len < 0)
	{
		*content_len = 0;
		*content = (unsigned char *) (pPacket + ll_head_len + ip_head_len);
	}
	else
	{
		*content = (unsigned char *) (pPacket + ll_head_len + ip_head_len + l4_head_len);
	}
	if (iCapLen < (ll_head_len + ip_head_len + l4_head_len))
	{
		return BEAP_FAIL;
	}
	return BEAP_SUCCESS;
}

char GetPortInfo(L3HeadStru struL3Head, L4HeadUnion unionL4Head, short *sport, short *dport)
{
	if (struL3Head.protocol == TCP_PROTO)
	{
		*sport = unionL4Head.TCPHead.source_port;
		*dport = unionL4Head.TCPHead.dest_port;
		return BEAP_SUCCESS;
	}
	else if (struL3Head.protocol == UDP_PROTO)
	{
		*sport = unionL4Head.UDPHead.source_port;
		*sport = unionL4Head.UDPHead.dest_port;
		return BEAP_SUCCESS;
	}
	return BEAP_FAIL;
}


void pkt_exec_receiver(const struct pcap_pkthdr *pHead, unsigned char *pPacket, unsigned int iCapLen, struct timeval t)
{
	unsigned int i = 0;
	LLHeadStru struLLHead;
	L3HeadStru struL3Head;
	L4HeadUnion unionL4Head;
	int content_len = 0;
	short sport = 0, dport = 0;
	unsigned char *content = NULL;
	char http_head_flag = 0;
	int http_joint_flag = 0;
	int join_flag = 0;

	int ret = AnalysisPacket(pPacket, iCapLen, &struLLHead, &struL3Head, &unionL4Head, &content, &content_len);
	if (ret == BEAP_FAIL)
	{
		return;
	}

	if (GetPortInfo(struL3Head, unionL4Head, &sport, &dport) == BEAP_FAIL)
	{
		return;
	}

	if (content_len > 0)
	{
	}
	return;
}

// END OF THE FILE

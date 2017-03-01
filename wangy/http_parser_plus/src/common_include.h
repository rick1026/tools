/***************************************************************************
 *   Copyright (C) 2015 by zhangjl                                         *
 *   zhangjl@qzt360.com                                                    *
 *                                                                         *
 ***************************************************************************/
#ifndef __COMMON_INCLUDE_H
#define __COMMON_INCLUDE_H

#include <pcap.h>
#include <getopt.h>
#include <sys/poll.h>
#include <stdint.h>
#include <sys/socket.h>

#include "data_def.h"
#include "linux_list.h"
//#include "tcp_reassemble.h"
//#include "cache_conn_hash.h"
//#include "http_cache.h"

void packet_processer(unsigned char *arg, const struct pcap_pkthdr *ph, const unsigned char *packet);

int DoTCPPacketProcess(const LLHeadStru *pStruLLHead,
                       const L3HeadStru *pStruL3Head,
                       const L4HeadUnion *pUnionL4Head,
                       unsigned int sip,
                       unsigned short sport,
                       unsigned int dip,
                       unsigned short dport,
                       const unsigned char *pContent,
                       const unsigned int content_len);


#endif
// end of the file

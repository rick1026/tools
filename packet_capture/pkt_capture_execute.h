/***************************************************************************
 *  MTB -- MultiThread Booster Engine for Wisetone QZT                      *
 *         by Brian He   Sep 2011                                           *
 ***************************************************************************/

#ifndef _BEAP_PKT_EXECUTE_H
#define _BEAP_PKT_EXECUTE_H


#include <pcap/pcap.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void pkt_exec_receiver(const struct pcap_pkthdr *pHead, unsigned char *packet, unsigned int caplen,
		struct timeval t);

#endif

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
#include "UDPServer.h"
#include "TCPServer.h"


class cls_pkt_processor
{
private:


    CUDPServer *udp_comm;
    CTCPServer *tcp_comm;

    ////// all the effective policies

    
public:
  cls_pkt_processor();
  cls_pkt_processor(int);
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

	static void *radom_work_func(void*);
    void do_radom_work(void*);



private:
};

#endif


// end of the file

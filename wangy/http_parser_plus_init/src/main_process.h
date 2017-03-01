/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *                                                                         *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
#ifndef __MAIN_PROCESS_H
#define __MAIN_PROCESS_H

#include <pcap.h>
#include "pkt_processor.h"

class cls_mainproc
{
private:
    cls_pkt_processor pkt_processor;

public:
    void packet_processer(unsigned char *arg, const struct pcap_pkthdr *ph, const unsigned char *packet);
        
};

#endif
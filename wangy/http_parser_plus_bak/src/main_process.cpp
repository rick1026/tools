/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "main_process.h"

void cls_mainproc::packet_processer(unsigned char *arg, const struct pcap_pkthdr *ph, const unsigned char *packet)
{
    printf("\n\n");
    static unsigned long  cap_pkt_cnt = 0;
    LLHeadStru            struLLHead;
    L3HeadStru            struL3Head;
    UDPHeadStru           struUDPHead;
    TCPHeadStru           struTCPHead;
    L4HeadUnion           unionL4Head;
    unsigned char         *pContent;
    unsigned int          caplen;
    unsigned int          ll_head_len;
    unsigned int          ip_head_len, iplen;
    unsigned int          tcp_head_len;
    unsigned int          content_len;

    caplen = ph->caplen;
    struLLHead = *(LLHeadStru *)packet;
    struLLHead.protocol = ntohs(struLLHead.protocol);

    //printf("\n\n===================packet_processer: recv (((((((%lu)))))) packet, caplen = %d\n", cap_pkt_cnt++, caplen);

    pContent = NULL;

    if (struLLHead.protocol==IP_PROTO)
    {
        ll_head_len = SIZE_BASE_LL_HEAD;
        if (caplen < ll_head_len)
        {
            return;
        }
        struLLHead.vlan_id = -1;
    }
    else
    {
        return;
    }

    if (caplen < ll_head_len)
    {
        return;
    }
    unsigned char *pPacket_begin  = NULL;
    pPacket_begin = (unsigned char*)packet;

    struL3Head = *(L3HeadStru *)(pPacket_begin + ll_head_len);
    struL3Head.source_addr = ntohl(struL3Head.source_addr);
    struL3Head.dest_addr = ntohl(struL3Head.dest_addr);
    struL3Head.total_len = ntohs(struL3Head.total_len);

    ip_head_len = (struL3Head.version & 0x0f) * 4;

    iplen = (struL3Head.total_len > caplen)? caplen:struL3Head.total_len;
    if (ip_head_len > iplen)
    {
        ip_head_len = 20; // minimum len for ip header in case of SERIOUS ABNORMALTY
    }

    if (caplen < SIZE_LL_HEAD + ip_head_len||struL3Head.total_len > caplen)
    {
        return;
    }

    // deal with the head sector according the protocol of 3rd layer
    switch (struL3Head.protocol)
    {
        case  TCP_PROTO:
            struTCPHead = *(TCPHeadStru *)(pPacket_begin + ll_head_len + ip_head_len);
            struTCPHead.source_port = ntohs(struTCPHead.source_port);
            struTCPHead.dest_port = ntohs(struTCPHead.dest_port);
            struTCPHead.seq_num = ntohl(struTCPHead.seq_num);
            struTCPHead.ack_num = ntohl(struTCPHead.ack_num);
            unionL4Head.TCPHead = struTCPHead;
            tcp_head_len = ((struTCPHead.header_len & 0xf0) >> 4) * 4;
            if ((tcp_head_len + ip_head_len) > iplen)
            {
                tcp_head_len = (iplen - ip_head_len < 0)? 0:iplen - ip_head_len;
            }
            pContent = /*(char *)*/(pPacket_begin + ll_head_len + ip_head_len + tcp_head_len);
            content_len = iplen - ip_head_len - tcp_head_len;
            if (caplen < ll_head_len + ip_head_len + tcp_head_len)
            {
                return;
            }

            break;
        case  UDP_PROTO:
            struUDPHead = *(UDPHeadStru *)(pPacket_begin + ll_head_len + ip_head_len);
            struUDPHead.source_port = ntohs(struUDPHead.source_port);
            struUDPHead.dest_port = ntohs(struUDPHead.dest_port);
            unionL4Head.UDPHead = struUDPHead;
            content_len = iplen - ip_head_len - SIZE_UDP_HEAD;
            if (content_len < 0)
            {
                content_len = 0;
                pContent =/*(char *)*/(pPacket_begin + ll_head_len + ip_head_len);
            }
            else
                pContent =/*(char *)*/(pPacket_begin + ll_head_len + ip_head_len + SIZE_UDP_HEAD);
            if (caplen < ll_head_len + ip_head_len + SIZE_UDP_HEAD)
            {
                return;
            }
            break;

        default:
            memset(&unionL4Head, 0, sizeof(L4HeadUnion));
            pContent =/*(char *)*/(pPacket_begin + ll_head_len + ip_head_len);
            content_len = iplen - ip_head_len;
    }

    if (pContent == NULL)
        return;

    //  END OF switch (struL3Head.protocol)
    if (content_len < 0)
        content_len = 0;

    unsigned short        sport = 0, dport = 0;

    sport = unionL4Head.TCPHead.source_port;
    dport = unionL4Head.TCPHead.dest_port;

    if(sport == 22 || dport == 22)
    {
        return;
    }

    unsigned int sip = struL3Head.source_addr;
    unsigned int dip = struL3Head.dest_addr;


    char str_sip[16], str_dip[16];
    bzero(str_sip, sizeof(str_sip));
    bzero(str_dip, sizeof(str_dip));

    struct in_addr addr;
    addr.s_addr = htonl(sip);
    strcpy(str_sip, inet_ntoa(addr));
    addr.s_addr = htonl(dip);
    strcpy(str_dip, inet_ntoa(addr));
    //printf("packet_processer: sip = %u, dip = %u, sport = %d, dport = %d\n", sip, dip, (int)sport, (int)dport);
    printf("packet_processer: sip = %s, sport = %d, dip = %s, dport = %d, caplen = %d, len = %d, content_len = %d\n",
           str_sip, (int)sport, str_dip, (int)dport, ph->caplen, ph->len, content_len);

    // only the TCP packet will be processed
    if (struL3Head.protocol != TCP_PROTO)
    {
        return;
    }

    if (content_len == 0)
    {
        printf("packet_processer: content_len == 0, return!\n");
        return;
    }
    else
        printf("packet_processer: content_len = %d, addr_pContent = %p, addr_packet = %p\n", content_len, pContent, packet);


    pkt_processor.DoTCPPacketProcess(&struLLHead,
                        &struL3Head,
                        &struTCPHead,
                        struL3Head.source_addr,
                        struTCPHead.source_port,
                        struL3Head.dest_addr,
                        struTCPHead.dest_port,
                        pContent,
                        content_len);

}

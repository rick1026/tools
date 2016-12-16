/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
#ifndef __TCP_REASSEMBLE_H
#define __TCP_REASSEMBLE_H

#include <stdint.h>
#include <semaphore.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "beap_hash.h"

#define MAX_SIZE_TCP_HASH   4096
#define MAX_INDEX_TCP_HASH  (MAX_SIZE_TCP_HASH - 1)

#define TCP_TIME_OUT    45

// tcp status
#define TCP_SEG_RECVING 0
#define TCP_SEG_RECVED  1
#define TCP_CLOSED      2
#define TCP_SEG_NULL    3
#define TCP_TIMEOUT     4

// tcp flag
#define TCP_FLAG_ACK        0x10
#define TCP_FLAG_FIN        0x01
#define TCP_FLAG_SYN        0x02
#define TCP_FLAG_SYN_ACK    0x12
#define TCP_FLAG_RST        0x04
#define TCP_FLAG_PSH        0x08

// tcp resource limit
#define TCP_SDU_LEN_THR     512000
#define MAX_TCP_SEG_LEN     513000

#define TCP_OS_BOUND1       0xfff7ffff
#define TCP_OS_BOUND2       0x80000

#define IS_SEQ_LARGER(a,b) \
            (((a) > (b) && ((b) > TCP_OS_BOUND2 || (a) < TCP_OS_BOUND1)) || \
            ((b) > TCP_OS_BOUND1) && (a) < TCP_OS_BOUND2)

#define IS_SEQ_ELARGER(a,b) \
        ((a) == (b) || ((a) > (b) && ((b) > TCP_OS_BOUND2 || (a) < TCP_OS_BOUND1)) || \
        ((b) > TCP_OS_BOUND1) && (a) < TCP_OS_BOUND2)


typedef struct{
    unsigned char   proto;
    unsigned int    src_ip;
    unsigned int    dst_ip;
    unsigned short    src_port;
    unsigned short    dst_port;
}TCPsessionID;

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



enum TCPDirection{
    DIR_NONE = 0,
    FROM_CLIENT = 1,
    FROM_SERVER = 2
};


typedef struct{
    TCPsessionID            id;
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

unsigned int tcp_sess_hash(void *key);
unsigned char tcp_sess_comp(void *key1, void *key2);

// uint32_t is defined in file stdint.h
class cls_tcp_reassemble
{
    private:
        sem_t               sem_hash;
        hash_table          *tcp_reassemble_tbl;
        pthread_t           hdl_hash_timer_thr;

    private:
        static void         *tcp_reassemble_tbl_timer(void *arg);
        void                do_timer();

        char                processSDU(const unsigned char* pContent, unsigned int content_len,
                                         TCPSduCb** pSDU_CB_head, TCPSduCb** pSDU_CB_tail,
                                         unsigned char ** data_buf, unsigned int *data_len,
                                         TCPHeadStru* head, unsigned int *bytes,
                                         unsigned int init_seq, unsigned int *min_seq, unsigned int *push_num);
        TCPSduCb            *allocate_cb(TCPSduCb *cb1, TCPSduCb *cb2,
                                           unsigned char *copy_from, unsigned int from_seq, unsigned int to_seq,
                                           unsigned int copy_len);
        void                freeSDUcb(TCPSduCb** pSDU_CB_head);



    public:
        cls_tcp_reassemble();
		~cls_tcp_reassemble();


        char do_tcp_reassemble(unsigned int src_ip, unsigned int dst_ip,
                               unsigned short src_port,unsigned short dst_port,
                               int *dir, //unsigned char dir,
                               TCPHeadStru *head,
                               const unsigned char *pContent,unsigned int content_len,
                               unsigned int *data_len,unsigned char **data_buf);
        
};

#endif
   

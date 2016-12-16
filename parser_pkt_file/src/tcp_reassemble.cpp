/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tcp_reassemble.h"

//#define __TCP_REASSEMBLE_LOG

#define MAX_SIZE_TCP_HASH   4096
#define MAX_INDEX_TCP_HASH  (MAX_SIZE_TCP_HASH - 1)


unsigned int tcp_sess_hash(void *key)
{
  int       i;
  unsigned int ret = 0;

  for (i = 0; i < sizeof(TCPsessionID); i += 2)
    ret += *((unsigned char*)((unsigned char*)key + i));

  return ret & MAX_INDEX_TCP_HASH;
}

unsigned char tcp_sess_comp(void *key1, void *key2)
{
  TCPsessionID  *tcp_id1, *tcp_id2;

  if (!memcmp(key1, key2, sizeof(TCPsessionID)))
    return 0;

  tcp_id1 = (TCPsessionID *) key1;
  tcp_id2 = (TCPsessionID *) key2;
  if (tcp_id1 -> src_ip == tcp_id2 -> dst_ip &&\
      tcp_id1 -> dst_ip == tcp_id2 -> src_ip &&\
      tcp_id1 -> src_port == tcp_id2 -> dst_port &&\
      tcp_id1 -> dst_port == tcp_id2 -> src_port)
    return 0;
  return 1;
}


cls_tcp_reassemble::cls_tcp_reassemble()
{
  if (sem_init(&sem_hash, 0, 1) == -1)
  {
    printf("sem_init sem_hash error, exit!\n");
    exit(1);
  }

  if ((tcp_reassemble_tbl = create_hash(MAX_SIZE_TCP_HASH, tcp_sess_hash, tcp_sess_comp)) == NULL)
  {
    printf("tcp_reassemble_init: create_hash error, exit!\n");
    exit(1);
  }

  printf("cls_tcp_reassemble(): addr of tcp_reassemble_tbl = %p\n", tcp_reassemble_tbl);

  pthread_create(&hdl_hash_timer_thr, NULL, tcp_reassemble_tbl_timer, (void*)this);
}

cls_tcp_reassemble::~cls_tcp_reassemble()
{
}

void* cls_tcp_reassemble::tcp_reassemble_tbl_timer(void *arg)
{
  cls_tcp_reassemble *pThis = reinterpret_cast<cls_tcp_reassemble*>(arg);

  pThis->do_timer();
}

void cls_tcp_reassemble::do_timer()
{
  while(1)
  {
    sleep(5);
    printf("%u, tcp_reassemble_do_time do_timer() running, addr of tcp_reassemble_tbl = %p!!!\n", time(0), tcp_reassemble_tbl);
  }

}

char cls_tcp_reassemble::do_tcp_reassemble(unsigned int src_ip, unsigned int dst_ip,
    unsigned short src_port,unsigned short dst_port,
    int *dir, //unsigned char dir,
    TCPHeadStru *head,
    const unsigned char *pContent,unsigned int content_len,
    unsigned int *data_len,unsigned char **data_buf)
{
  char         ret_val;
  TCPsessionID tcp_id;
  hash_bucket  *pBucket = NULL;
  char         got_sdu = 0; // flag to mark if a sdu is getted
  char         to_continue = 1; // flag to mark if the processing of the packet will go on
  TCPsession   *p_tcp_session = NULL;
  char         flag_pkt_sender = 0; // flag to mark if the packet belongs to the sender of the connection

  // 设置连接拆除标记,当为RESET报文或收到两个FIN后可以即时将连接拆除状态传回,供其他情况及时清理资源
  char rst_flag = 0;

  // create key of current tcp conn
  // the compare function of tcp_session_tbl_ec will ignore the direction of the packet, that means
  // the find_hash will return the same tcp connection as long as the packet belongs to the connection.
  bzero(&tcp_id, sizeof(tcp_id));
  tcp_id.src_ip = src_ip;
  tcp_id.dst_ip = dst_ip;
  tcp_id.src_port = src_port;
  tcp_id.dst_port = dst_port;

#ifdef __TCP_REASSEMBLE_LOG
  printf("process_tcp_packet: find_hash from tcp_reassemble_tbl by tcp_id\n");
#endif

  pBucket = find_hash(tcp_reassemble_tbl, &tcp_id);
  if(pBucket == NULL)
  {
#ifdef __TCP_REASSEMBLE_LOG
    printf("process_tcp_packet: find_hash==NULL, alloc a new session inserted into hash\n");
#endif

    p_tcp_session = (TCPsession*)malloc(sizeof(TCPsession));
    memset(p_tcp_session, 0, sizeof(TCPsession));
    memcpy(&p_tcp_session->id, &tcp_id, sizeof(TCPsessionID));
    p_tcp_session->init_forward_seq = head->seq_num;

    if ((head->flags & TCP_FLAG_SYN) == 0)
    {
      p_tcp_session->state = ESTAB;
#ifdef __TCP_REASSEMBLE_LOG
      printf("process_tcp_packet: new bucket, no SYN flag, set p_tcp_session->state=ESTAB\n");
#endif

    }
    else
    {
      p_tcp_session->state = SYN_SENT;
      to_continue = 0;
#ifdef __TCP_REASSEMBLE_LOG
      printf("process_tcp_packet, new bucket, SYN flag packet, set p_tcp_session->state=SYN_SENT and to_continue=0\n");
#endif

    }

    // added by zhangjl
    // 报文只有SYN标记置位,则为TCP连接的第一个报文,从CLIENT端发出, 设置连接信息如下:
    // 初始状态为SYN_SENT,初始forward_seq为当前SYN报文的seq+1,无有效负载,因此to_continue=0, dir=FROM_CLIENT
    if ((head->flags ^ TCP_FLAG_SYN) == 0)// only the SYN flag is set, the packet is the first SYN packet of the connection-sender
    {
      p_tcp_session->state = SYN_SENT;
      p_tcp_session->init_forward_seq = head->seq_num + 1; // get the first seq of the sender
      to_continue = 0; // set the flag to false only when the packet is the first SYN packet of the sender
      *dir = FROM_CLIENT;
#ifdef __TCP_REASSEMBLE_LOG
      printf("process_tcp_packet, SYN packet, set state=SYN_SEND, init_forward_seq = %u\n", head->seq_num + 1);
#endif
    }
    // 报文的SYN_ACK标记置位,则为TCP连接的第二个报文,从SERVER端发出,设置连接信息如下:
    // 连接状态为SYN_RECVD,设置初始forward_seq为ack_seq(报文不丢失的情况下这个值等于SYN报文中的seq+1), 初始backward_seq
    // 为当前SYN-ACK报文的seq+1, dir=FROM_SERVER
    else if ((head->flags ^ TCP_FLAG_SYN_ACK) == 0) // SYN_ACK packet, the first packet of the connection-receiver
    {
      p_tcp_session->state = SYN_RECVD;
      p_tcp_session->init_forward_seq = head->ack_num; // get the first seq of the sender
      p_tcp_session->init_backward_seq = head->seq_num + 1; // get the first seq of the receiver
      *dir = FROM_SERVER;
#ifdef __TCP_REASSEMBLE_LOG
      printf("process_tcp_packet, SYN-ACK packet, set state=SYN_RECVD, init_forward_seq = %u\n", head->ack_num);
#endif
    }
    else if ((head->flags ^ TCP_FLAG_RST) == 0)
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("---------head->flags = %02x\n", head->flags);
      printf("process_tcp_packet, RST packet, to_continue == 0, goto tcp_proc_done\n", head->ack_num);
#endif
      to_continue = 0;
      goto tcp_proc_done;
    }
    // 若进入这个分支,说明TCP三次握手的SYN和SYN-ACK报文已经丢失,这种情况下将此连接上第一个报文的seq_num作为初始的forward_seq,
    // 将第一个报文的ack_num作为初始的backward_seq,并直接设置连接状态为ESTAB. 这种处理方式可能发生以下错误
    // (1) 此连接上的第一个报文实际是从SERVER发往CLIENT的,会使得方向判断出错,进而影响后续协议处理(如HTTP协议)---可以检验
    //     第一个报文是否GET或POST来决定是否继续重组
    // (2) 丢包严重时,收到第一个报文之后,又收到了实际seq_num小于这个报文的报文,意味着报文乱序,这时,会引起数据丢失
    // (3) 其他可能但尚未想到的问题
    // 目前,暂时想不到更好的办法来处理这种情况,只好先这样了??????????
    else
    {
      // if runs here, it means the syn and syn/ack packets has losed, in which case the tcp reassemble's result
      // may be not correct, set the first seq of the sender as the seq of the packet(we can do nothing beside this)
      p_tcp_session->state = ESTAB;
      p_tcp_session->init_forward_seq = head->seq_num;
      p_tcp_session->init_backward_seq = head->ack_num;
      *dir = FROM_CLIENT;
#ifdef __TCP_REASSEMBLE_LOG
      printf("process_tcp_packet, other packet, state=ESTAB, init_forward_seq = %u\n", head->ack_num);
#endif
    }
    // ended added

    // make sure the information of the session's tcp_id is always the same to the sender of the connection
    // 根据方向来调整tcp_id的值,确保插入hash表中的所有节点,其key值信息都是和连接发起方一致的
    if ((*dir) != FROM_CLIENT)
    {
      tcp_id.src_ip = dst_ip;
      tcp_id.dst_ip = src_ip;
      tcp_id.src_port = dst_port;
      tcp_id.dst_port = src_port;
    }
    p_tcp_session->sender_ip = tcp_id.src_ip;

    // 将此新连接的信息插入hash表中
    memcpy(&p_tcp_session->id, &tcp_id, sizeof(TCPsessionID));
    p_tcp_session->time_stamp = TCP_TIME_OUT;
    pBucket = (hash_bucket*)malloc(sizeof(hash_bucket));
    pBucket->content = (void *)p_tcp_session;
    pBucket->key = &(p_tcp_session->id);
    insert_hash(tcp_reassemble_tbl, pBucket);
  }
  // 对于已有连接,在插入hash时已经保证其key值信息都是和连接发起方一致的,因此这里可以根据
  // 当前报文的sip和发起方ip比较,进而判断出报文的方向
  else
  {
    p_tcp_session = (TCPsession*)(pBucket->content);
    *dir = (p_tcp_session->sender_ip == src_ip) ? FROM_CLIENT : FROM_SERVER;
  }

  
  if(to_continue)
  {
    // 更新TCP连接的超时时间,每收到新报文,都更新为TCP_TIME_OUT
    p_tcp_session = (TCPsession *)(pBucket->content);
    p_tcp_session->time_stamp = TCP_TIME_OUT;

#ifdef __TCP_REASSEMBLE_LOG
    printf("process_tcp_packet: to_continue == 1, go on reassembling\n");
#endif
    // if the connection is reset, discard all the cache packet, free both the forward and backword link list,
    // remove the connection from the hash_tbl
    if((head->flags & TCP_FLAG_RST) != 0)
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("process_tcp_packet: RST_FLAG is TRUE, remove node from hash, goto tcp_proc_done\n");
#endif
      remove_hash(tcp_reassemble_tbl, pBucket);
      freeSDUcb(&p_tcp_session->forward_sdu_cb_head);
      freeSDUcb(&p_tcp_session->backward_sdu_cb_head);
      p_tcp_session->forward_sdu_cb_head = NULL;
      p_tcp_session->backward_sdu_cb_head = NULL;
      free(pBucket->content);
      free(pBucket);

      rst_flag = TCP_FLAG_RST;
      goto tcp_proc_done;
    }

    // 如果在三次握手过程中最后一个ACK丢失,则直接置连接状态为ESTABLISH
    if (content_len > 0 && p_tcp_session->state == SYN_RECVD)
      p_tcp_session->state = ESTAB;

    if(content_len > 0 &&(p_tcp_session->state == ESTAB ||
                          p_tcp_session->state == FIN_WAIT_1  ||
                          p_tcp_session->state == FIN_WAIT_2 ))
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("process_tcp_packet: content_len > 0 && ESTAB||FIN_WAIT_1||FIN_WAIT_2\n");
#endif
      // forward direction, the packet's direction is in accord with the first packet of the session
      // 报文的源IP和连接KEY值的源IP一致,说明报文是从连接发起方,即从CLIENT端发往SERVER的,这时若连接的上行
      // 方向的初始seq_no尚未得到,则从当前报文中取出seq_no作为初始forward_seq,并置位获取标记
      //if(tcp_id.src_ip == p_tcp_session->id.src_ip && p_tcp_session->forward_min_got == 0)
      if (p_tcp_session->forward_min_got == 0 && tcp_id.src_ip == p_tcp_session->id.src_ip)
      {
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: forward direction, forward_min_got==0, set forward_min_seq==seq_no, forward_min_got=1\n");
#endif
        p_tcp_session->forward_min_seq = head->seq_num;
        p_tcp_session->forward_min_got = 1;
      }
      // backward direction, the packet's direction is opposite to the first packet of the session
      // 报文的源IP和连接KEY值的源IP不同,说明报文是从SERVER端发往CLIENT的,这时若连接的下行方向的初始seq_no尚未得到,
      // 则从当前报文中取出seq_no作为初始backward_seq,并置位获取标记
      //if(tcp_id.src_ip != p_tcp_session->id.src_ip && p_tcp_session->backward_min_got == 0)
      if(p_tcp_session->backward_min_got == 0 && tcp_id.src_ip != p_tcp_session->id.src_ip)
      {
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: backward direction, backward_min_got==0, set backward_min_seq==seq_no, backward_min_got=1\n");
#endif
        if (p_tcp_session->init_backward_seq < head->seq_num)
          p_tcp_session->backward_min_seq = p_tcp_session->init_backward_seq;
        else
          p_tcp_session->backward_min_seq = head->seq_num;

        p_tcp_session->backward_min_got = 1;
      }

      /*
      // added by zhangjl
      else
      {
          if (p_tcp_session->backward_min_seq > head->seq_num)
              p_tcp_session->backward_min_seq = head->seq_num;
      }*/
      // end added
      if(tcp_id.src_ip == p_tcp_session->id.src_ip)
      {
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: forward direction, call processSDU, forward_bytes=%u, init_forward_seq=%u,forward_min_seq=%u,forward_push_num=%u\n",
               p_tcp_session->forward_bytes, p_tcp_session->init_forward_seq, p_tcp_session->forward_min_seq, p_tcp_session->forward_push_num);
#endif
        ret_val = processSDU(pContent, content_len, &(p_tcp_session->forward_sdu_cb_head), &(p_tcp_session->forward_sdu_cb_tail),
                             data_buf, data_len, head, &(p_tcp_session->forward_bytes), p_tcp_session->init_forward_seq,
                             &(p_tcp_session->forward_min_seq), &(p_tcp_session->forward_push_num));
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: call processSDU return_val=%d, forward_bytes=%u, init_forward_seq=%u,forward_min_seq=%u,forward_push_num=%u\n", ret_val,
               p_tcp_session->forward_bytes, p_tcp_session->init_forward_seq, p_tcp_session->forward_min_seq, p_tcp_session->forward_push_num);
#endif
        switch(ret_val)
        {
        case    1:
          got_sdu = 1;
          break;
        case    2:
          break;
        case    3:
          got_sdu = 1;
          break;
        default:
          break;
        }
      }

      if(tcp_id.src_ip != p_tcp_session->id.src_ip)
      {
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: backward direction, call processSDU, backward_bytes=%u, init_backward_seq=%u,backward_min_seq=%u,backward_push_num=%u\n",
               p_tcp_session->backward_bytes, p_tcp_session->init_backward_seq, p_tcp_session->backward_min_seq, p_tcp_session->backward_push_num);
#endif
        ret_val = processSDU(pContent, content_len,
                             &p_tcp_session->backward_sdu_cb_head, &p_tcp_session->backward_sdu_cb_tail,
                             data_buf, data_len, head, &p_tcp_session->backward_bytes, p_tcp_session->init_backward_seq,
                             &p_tcp_session->backward_min_seq, &p_tcp_session->backward_push_num);
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: call processSDU return_val=%d, backward_bytes=%u, init_backward_seq=%u,backward_min_seq=%u,backward_push_num=%u\n", ret_val,
               p_tcp_session->backward_bytes, p_tcp_session->init_backward_seq, p_tcp_session->backward_min_seq, p_tcp_session->backward_push_num);
#endif
        switch(ret_val)
        {
        case    1:
          got_sdu = 1;
          break;
        case    2:
          break;
        case    3:
          got_sdu = 1;
          break;
        default:
          break;
        }
      }
    }
    else
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("process_tcp_packet: content_len < 0 or others, go on switch\n");
#endif

    }

#ifdef __TCP_REASSEMBLE_LOG
    printf("process_tcp_packet: go on switch .............\n");
#endif
    switch(p_tcp_session->state)
    {
    case    SYN_SENT:
      if(tcp_id.src_ip == p_tcp_session->id.dst_ip &&
          (head->flags & TCP_FLAG_SYN) != 0 &&
          (head->flags & TCP_FLAG_ACK) != 0)
      {
        p_tcp_session->state = SYN_RECVD;
        p_tcp_session->init_backward_seq = head->seq_num + 1;
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: switch, sess_state changed from SYN_SENT to SYN_RECVED\n");
#endif
        break;
      }

      if (tcp_id.src_ip == p_tcp_session->id.dst_ip &&
          (head->flags & TCP_FLAG_SYN) != 0 &&
          (head->flags & TCP_FLAG_ACK) == 0)
      {
        p_tcp_session->state = SYN_SIM;
        p_tcp_session->init_backward_seq = head->seq_num + 1;
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: switch, sess_state changed from SYN_SENT to SYN_SIM\n");
#endif
        break;
      }

      if ((tcp_id.src_ip == p_tcp_session->id.src_ip) && ((head->flags & TCP_FLAG_ACK) == 0))
      {
        p_tcp_session->init_backward_seq = head->ack_num;
      }
      break;
    case    SYN_RECVD:
      if(tcp_id.src_ip == p_tcp_session->id.src_ip && (head->flags & TCP_FLAG_ACK) != 0)
      {
        p_tcp_session->state = ESTAB;
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: switch, sess_state changed from SYN_RECVD to ESTAB\n");
#endif
        break;
      }
      break;
    case    SYN_SIM:
      if ((head->flags & TCP_FLAG_ACK) != 0)
      {
        p_tcp_session->state = ESTAB;
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: switch, sess_state changed from SYN_SIM to ESTAB\n");
#endif
        break;
      }
      break;
    case    ESTAB:
      if ((head->flags & TCP_FLAG_FIN) != 0)
      {
        p_tcp_session->fin_sender = tcp_id.src_ip;
        p_tcp_session->state = FIN_WAIT_1;
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: switch, sess_state changed from ESTAB to FIN_WAIT_1\n");
#endif

      }
      break;
    case    FIN_WAIT_1:
      if ((head->flags & TCP_FLAG_FIN) != 0)
      {
        if(tcp_id.src_ip != p_tcp_session->fin_sender)
        {
          p_tcp_session->state = CLOSING;
          // added by zhangjl
          remove_hash(tcp_reassemble_tbl, pBucket);
          freeSDUcb(&p_tcp_session->forward_sdu_cb_head);
          freeSDUcb(&p_tcp_session->backward_sdu_cb_head);
          p_tcp_session->forward_sdu_cb_head = NULL;
          p_tcp_session->backward_sdu_cb_head = NULL;
          free(pBucket->content);
          free(pBucket);
          rst_flag = TCP_FLAG_RST;
          // end added
#ifdef __TCP_REASSEMBLE_LOG
          printf("process_tcp_packet: switch, sess_state changed from FIN_WAIT_1 to CLOSING, remove session from hash_tbl\n");
#endif

        }
        break;
      }
      if ((head->flags & TCP_FLAG_ACK) != 0)
      {
        if(tcp_id.src_ip != p_tcp_session->fin_sender)
        {
          if ((head->flags & TCP_FLAG_FIN) != 0)
          {
            p_tcp_session->state = LAST_ACK;
#ifdef __TCP_REASSEMBLE_LOG
            printf("process_tcp_packet: switch, sess_state changed from FIN_WAIT_1 to LAST_ACK\n");
#endif

          }
          else
          {
            p_tcp_session->state = FIN_WAIT_2;
#ifdef __TCP_REASSEMBLE_LOG
            printf("process_tcp_packet: switch, sess_state changed from FIN_WAIT_1 to FIN_WAIT_2\n");
#endif

          }
        }
        break;
      }
      break;
    case    FIN_WAIT_2:
      if ((head->flags & TCP_FLAG_FIN) != 0)
      {
        if(tcp_id.src_ip != p_tcp_session->fin_sender)
        {
          p_tcp_session->state = LAST_ACK;
#ifdef __TCP_REASSEMBLE_LOG
          printf("process_tcp_packet: switch, sess_state changed from FIN_WAIT_2 to LAST_ACK\n");
#endif

        }
        break;
      }
      break;
    case    LAST_ACK:
      if ((head->flags & TCP_FLAG_ACK) != 0)
      {
        if(tcp_id.src_ip == p_tcp_session->fin_sender)
        {
#ifdef __TCP_REASSEMBLE_LOG
          printf("process_tcp_packet: switch, sess_state recvd ACK_FLAG when LAST_ACK state, remove from hash\n");
#endif
          remove_hash(tcp_reassemble_tbl, pBucket);
          freeSDUcb(&p_tcp_session->forward_sdu_cb_head);
          freeSDUcb(&p_tcp_session->backward_sdu_cb_head);
          p_tcp_session->forward_sdu_cb_head = NULL;
          p_tcp_session->backward_sdu_cb_head = NULL;
          free(pBucket->content);
          free(pBucket);
          rst_flag = TCP_FLAG_RST;
        }
      }
      break;
    case    CLOSING:
      if ((head->flags & TCP_FLAG_ACK) != 0)
      {
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: switch, sess_state recvd ACK_FLAG when CLOSING state, remove from hash\n");
#endif
        remove_hash(tcp_reassemble_tbl, pBucket);
        freeSDUcb(&p_tcp_session->forward_sdu_cb_head);
        freeSDUcb(&p_tcp_session->backward_sdu_cb_head);
        p_tcp_session->forward_sdu_cb_head = NULL;
        p_tcp_session->backward_sdu_cb_head = NULL;
        free(pBucket->content);
        free(pBucket);
        rst_flag = TCP_FLAG_RST;
      }
      break;
    default:
      break;
    }
  }
  else
  {
#ifdef __TCP_REASSEMBLE_LOG
    printf("process_tcp_packet: to_continue == 0\n");
#endif
  }
tcp_proc_done:
  if (got_sdu == 1)
  {
    //*return_session = p_tcp_session;
#ifdef __TCP_REASSEMBLE_LOG
    printf("process_tcp_packet: got_sdu == 1, return TCP_SEG_RECVED\n");
#endif
    return TCP_SEG_RECVED | rst_flag;
  }
  else
  {
    //*return_session = p_tcp_session;
#ifdef __TCP_REASSEMBLE_LOG
    printf("process_tcp_packet: got_sdu == 0, return TCP_SEG_RECVING\n");
#endif
    return TCP_SEG_RECVING | rst_flag;
  }
}

char cls_tcp_reassemble::processSDU(const unsigned char* pContent, unsigned int content_len,
                                    TCPSduCb** pSDU_CB_head, TCPSduCb** pSDU_CB_tail,
                                    unsigned char ** data_buf, unsigned int *data_len,
                                    TCPHeadStru* head, unsigned int *bytes,
                                    unsigned int init_seq, unsigned int *min_seq, unsigned int *push_num)
{
  TCPSduCb            *cb1 = NULL, *cb2 = NULL, *cb3 = NULL;
  char                to_get = 0;
  char                error_logged = 0;
  unsigned int        start_seq, end_seq;

  if(content_len == 0)
  {
#ifdef __TCP_REASSEMBLE_LOG
    printf("processSDU: content == 0, goto pro_done\n");
#endif
    goto pro_done;
  }

  cb1 = *pSDU_CB_head;
  cb2 = *pSDU_CB_tail;

  start_seq = head->seq_num;
  end_seq = head->seq_num + content_len;

#ifdef __TCP_REASSEMBLE_LOG
  printf("processSDU: cb1 == head, cb2==tail\n");
  printf("processSDU: start_seq = %u, end_seq = %u\n", start_seq, end_seq);
  printf("processSDU: bytes = %u, init_seq = %u, min_seq = %u, push_num = %u\n", *bytes, init_seq, *min_seq, *push_num);
#endif

  if(IS_SEQ_LARGER(*min_seq, start_seq))
  {
#ifdef __TCP_REASSEMBLE_LOG
    printf("\tIS_SEQ_LARGER(min_seq, start_seq)\n");
#endif
    if (IS_SEQ_ELARGER(*min_seq, end_seq))
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("\tIS_SEQ_LARGER(min_seq, end_seq), set error_log=1, goto pro_done\n");
#endif
      error_logged = 1;
      goto pro_done;
    }
    else
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("\tnot IS_SEQ_LARGER(min_seq, end_seq), set error_log=1, start_seq=min_seq\n");
#endif
      start_seq = *min_seq;
      error_logged = 1;
    }
  }

  if ((head->flags & TCP_FLAG_PSH) != 0)
  {
#ifdef __TCP_REASSEMBLE_LOG
    printf("processSDU: head_push_flag is set\n");
#endif
    if (*push_num >= 2)
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("processSDU: head_push_flag is set and push_num>=2, set error_log=1\n");
#endif
      error_logged = 1;
    }
  }

  unsigned char *copy_from;
  unsigned int  from_seq, to_seq;
  unsigned int  copy_len;

  if(cb1 == NULL)
  {
    from_seq = start_seq;
    to_seq = end_seq;
    copy_from = (unsigned char*)pContent + from_seq - head->seq_num;
    copy_len = to_seq - from_seq;
#ifdef __TCP_REASSEMBLE_LOG
    printf("processSDU: cb1==NULL, from_seq = %u, to_seq = %u, copy_len = %u\n", from_seq, to_seq, copy_len);
#endif
    cb3 = allocate_cb(NULL, NULL, copy_from, from_seq, to_seq, copy_len);
    *pSDU_CB_head = *pSDU_CB_tail = cb3;

    // if the first packet with payload hash PSH or FIN flag, set PUSH_flag==1
    if (((head->flags & TCP_FLAG_PSH) != 0) || ((head->flags & TCP_FLAG_FIN) != 0 ))
    {
      cb3->PUSH_flaged = 1;
      (*push_num) ++;
#ifdef __TCP_REASSEMBLE_LOG
      printf("processSDU: cb1==NULL, push_flag or FIN_flag is set, set cb3->push_flag=1 and push_num=%u\n", *push_num);
#endif

    }
    (*bytes) += copy_len;

#ifdef __TCP_REASSEMBLE_LOG
    printf("processSDU: cb1==NULL, byte=byte+copy_len= %u\n", *bytes);
#endif
  }
  else
  {
#ifdef __TCP_REASSEMBLE_LOG
    printf("processSDU: cb1 != NULL.....................\n");
#endif
    while (cb2 != NULL)
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("while cb2 != NULL, set cb1 == cb2->prev_cb\n");
#endif
      cb1 = cb2->prev_cb;
      // the new packet is after the tail, append to the tail of the link_list
      if (cb2->next_cb == NULL && IS_SEQ_LARGER(end_seq, cb2->end_seq))
      {
#ifdef __TCP_REASSEMBLE_LOG
        printf("cb2->next_cb==NULL && end_seq(%u) is larger than cb2->end_seq(%u)\n", end_seq, cb2->end_seq);
#endif
        from_seq = (IS_SEQ_ELARGER(cb2->end_seq, start_seq))? cb2->end_seq:start_seq;
        to_seq = end_seq;
        copy_from = (unsigned char*)pContent + from_seq - head->seq_num;
        copy_len = to_seq - from_seq;
        cb3 = allocate_cb(cb2, NULL, copy_from, from_seq, to_seq, copy_len);
        *pSDU_CB_tail = cb3;
        if (((head->flags & TCP_FLAG_PSH) != 0) || ((head->flags & TCP_FLAG_FIN) != 0))
        {
          cb3->PUSH_flaged = 1;
          head->flags &= ~TCP_FLAG_PSH;
          (*push_num) ++;
        }
        (*bytes) += copy_len;
      }

      if (cb1 == NULL && IS_SEQ_LARGER(cb2->start_seq, start_seq))
      {
#ifdef __TCP_REASSEMBLE_LOG
        printf("cb1==NULL && cb2->start_seq(%u) is larger than start_seq(%u)\n", cb2->start_seq, start_seq);
#endif
        from_seq = start_seq;
        to_seq = (IS_SEQ_ELARGER(end_seq, cb2->start_seq))? cb2->start_seq:end_seq;
        copy_from = (unsigned char*)pContent + from_seq - head->seq_num;
        copy_len = to_seq - from_seq;
        cb3 = allocate_cb(NULL, cb2, copy_from, from_seq, to_seq, copy_len);
        *pSDU_CB_head = cb3;
        if (((head->flags & TCP_FLAG_PSH) != 0) || ((head->flags & TCP_FLAG_FIN) != 0))
        {
          cb3->PUSH_flaged = 1;
          head->flags &= ~TCP_FLAG_PSH;
          (*push_num) ++;
        }
        (*bytes) += copy_len;
      }
      if (cb1 != NULL && IS_SEQ_LARGER(cb2->start_seq, cb1->end_seq) && \
          IS_SEQ_ELARGER(end_seq, cb1->end_seq) && IS_SEQ_ELARGER(cb2->start_seq, start_seq))
      {
#ifdef __TCP_REASSEMBLE_LOG
        printf("cb1!=NULL && cb2->start_eq(%u) larger than cb1->end_seq(%u) && end_seq(%u) elarger than cb1->end_seq(%u) && cb2->start_seq(%u) elarger than start_seq(%u)\n",
               cb2->start_seq, cb1->end_seq, end_seq, cb1->end_seq, cb2->start_seq, start_seq);
#endif
        from_seq = (IS_SEQ_ELARGER(cb1->end_seq, start_seq))? cb1->end_seq:start_seq;
        to_seq = (IS_SEQ_ELARGER(end_seq, cb2->start_seq))? cb2->start_seq:end_seq;
        copy_from = (unsigned char*)pContent + from_seq - head->seq_num;
        copy_len = to_seq - from_seq;
        if (copy_len > 0)
        {
          cb3 = allocate_cb(cb1, cb2, copy_from, from_seq, to_seq, copy_len);
          if (cb3 != NULL)
          {
            if (((head->flags & TCP_FLAG_PSH) != 0) || ((head->flags & TCP_FLAG_FIN) != 0))
            {
              cb3->PUSH_flaged = 1;
              head->flags &= ~TCP_FLAG_PSH;
              (*push_num) ++;
            }
          }
          (*bytes) += copy_len;
        }
      }

#ifdef __TCP_REASSEMBLE_LOG
      printf("set cb2== cb1...........\n");
#endif
      cb2 = cb1;
      if (cb2 != NULL && cb2->end_seq < start_seq)
      {
#ifdef __TCP_REASSEMBLE_LOG
        printf("cb2 != NULL && cb2->end_seq(%u) < start_seq(%u), break\n", cb2->end_seq, start_seq);
#endif
        break;
      }
    }
  }

  if (*bytes >= TCP_SDU_LEN_THR)
  {
    /*      cb3 = *pSDU_CB_head;
    int nodes;
    nodes = 0;
    while(cb3 != NULL){
    if (cb3->next_cb != NULL && cb3->end_seq != cb3->next_cb->start_seq)

    if (cb3->PUSH_flaged)

    if (cb3->end_seq - cb3->start_seq != cb3->data_len)

    cb3 = cb3->next_cb;
    nodes ++;
    }
    */

    error_logged = 1;
    to_get = 1;
  }
  else
  {
    cb1 = *pSDU_CB_head;
    if ((*push_num) > 0)
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("push_num=%u, min_seq=%u,cb1->start_seq=%u\n", *push_num, *min_seq, cb1->start_seq);
#endif
      if (cb1 != NULL && (IS_SEQ_ELARGER(*min_seq, cb1->start_seq)))
      {
#ifdef __TCP_REASSEMBLE_LOG
        printf("cb1 != NULL, min_seq(%u) >= cb1->start_seq(%u)\n", *min_seq, cb1->start_seq);
#endif
        to_get = 1;
        while(cb1 != NULL)
        {
#ifdef __TCP_REASSEMBLE_LOG
          printf("111111111111 cb1 != NULL\n");
#endif

#if 0
          if (cb1->PUSH_flaged && (IS_SEQ_ELARGER(init_seq,*min_seq)))
          {
            printf("cb1->PUSH_flaged, break, to_get==1\n");
            break;
          }

          // when the first sdu is getted, and the second sdu will cann't be getted for this condition,
          // this is a bug, we should save the largest seq has reassembled and compare to the min_seq
          // in here.
          if (cb1->PUSH_flaged && (IS_SEQ_LARGER(*min_seq, init_seq)))
          {
            to_get = 0;
            break;
          }
#endif
          if (cb1->PUSH_flaged)
          {
#ifdef __TCP_REASSEMBLE_LOG
            printf("cb1->PUSH_flaged, break, to_get==1\n");
#endif
            break;
          }

          // get a PSH packet, but there is hole before the seq of the PSH packet
          if (cb1->next_cb != NULL && IS_SEQ_LARGER(cb1->next_cb->start_seq, cb1->end_seq))
          {
#ifdef __TCP_REASSEMBLE_LOG
            printf("cb1->next_cb != NULL && cb1->next_cb->start_seq(%u) >= cb1->end_seq(%u), set to_get=0\n", cb1->next_cb->start_seq, cb1->end_seq);
#endif
            to_get = 0;
            //  error_logged = 1;
            break;
          }

          cb1 = cb1->next_cb;
        }
        if (cb1 == NULL)
        {
          *push_num = 0;
          to_get = 0;
        }
      }
    }
  }

  if (to_get)
  {
    cb1 = *pSDU_CB_head;
    cb2 = NULL;
    *data_len = 0;
    char len_exceed = 0;
    int temp_pos;

    // get the length of the reassembled SDU
    while(cb1 != NULL)
    {
      (*data_len) += cb1->data_len;
      cb1 = cb1->next_cb;
    }

    if (*data_len >= MAX_TCP_SEG_LEN)
      len_exceed = 1;

    *data_buf = (unsigned char*)malloc(*data_len);
    temp_pos = 0;

    // added by zhangjl on 20150127 to fix the bug that when a push packet of
    // a sdu and the first packet of the next sdu come before its some previous
    // packet, in which case the reassembled SDU's len is the length of the
    // real SDU+the length of the having comed packets of the next SDU's contious
    // packets, but only the length of the sdu's is correct. so clear the length
    // here and do accumulation addition when copy every packet of the sdu.
    *data_len = 0;

    cb1 = *pSDU_CB_head;
    while(cb1 != NULL)
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("while cb1 != NULL\n");
#endif
      if (len_exceed == 1)
      {
        error_logged = 1;
      }
      else
      {
        memcpy(*data_buf + temp_pos, cb1->data_buf, cb1->data_len);
        temp_pos += cb1->data_len;
      }
      (*bytes) -= cb1->data_len;
      // added by zhangjl on 20150127 to fix the bug referred above
      (*data_len) += cb1->data_len;
      // end added

      cb1->data_len = 0;
      // free(cb1->data_buf);
      cb2 = cb1->next_cb;
      (*min_seq) = cb1->end_seq;
#ifdef __TCP_REASSEMBLE_LOG
      printf("to_get==1, cb1 != NULL, set min_seq = cb1->end_seq = %u\n", *min_seq);
#endif
      if (cb1->PUSH_flaged)
      {
        (*push_num) --;
#ifdef __TCP_REASSEMBLE_LOG
        printf("to_get==1, cb1->PUSH_flaged, push_num-- = %u\n", *push_num);
#endif
        if (cb2 != NULL && IS_SEQ_LARGER(cb2->start_seq, cb1->end_seq))
        {
#ifdef __TCP_REASSEMBLE_LOG
          printf("cb2=cb1->next_cb != NULL && cb2->start_seq(%u) > cb1->end_seq(%u), free cb1 and break\n", cb2->start_seq, cb1->end_seq);
#endif
          free(cb1);
          break;
        }

#ifdef __TCP_REASSEMBLE_LOG
        printf("cb3=cb2=cb1->next_cb\n");
#endif
        cb3 = cb2;
        while (cb3 != NULL)
        {
#ifdef __TCP_REASSEMBLE_LOG
          printf("while cb3 != NULL\n");
#endif
          if (cb3->PUSH_flaged)
          {
#ifdef __TCP_REASSEMBLE_LOG
            printf("cb3->PUSH_flaged is set, break\n");
#endif
            break;
          }
          if (cb3->next_cb != NULL && IS_SEQ_LARGER(cb3->next_cb->start_seq, cb3->end_seq))
          {
#ifdef __TCP_REASSEMBLE_LOG
            printf("cb3->next_cb != NULL && cb3->next_cb->start_seq(%u) is larger than cb3->end_seq(%u), break\n", cb3->next_cb->start_seq, cb3->end_seq);
#endif
            break;
          }
          cb3 = cb3->next_cb;
#ifdef __TCP_REASSEMBLE_LOG
          printf("cb3 = cb3->next_cb, while cb3!= NULL continue\n");
#endif
        }
        if (cb3 == NULL || (cb3 != NULL && cb3->PUSH_flaged == 0))
        {
#ifdef __TCP_REASSEMBLE_LOG
          if (cb3 == NULL)
          {
            printf("cb3==NULL, free cb1 and break\n");
          }
          else
          {
            printf("cb3!= NULL && cb3->PUSH_flaged==0, free cb1 and break\n");
          }
#endif
          free(cb1);
          break;
        }
      }

      if (cb2 != NULL && IS_SEQ_LARGER(cb2->start_seq, cb1->end_seq))
      {
#ifdef __TCP_REASSEMBLE_LOG
        printf("cb2 != NULL &&cb2->start_seq(%u) is larger than cb1->end_seq(%u), free cb1 and break\n", cb2->start_seq, cb1->end_seq);
#endif
        free(cb1);
        break;
      }

      free(cb1);
      cb1 = cb2;
#ifdef __TCP_REASSEMBLE_LOG
      printf("free cb1, cb1 = cb2, while cb1!= NULL continue");
#endif

    }

    *pSDU_CB_head = cb2;
    if (cb2 != NULL)
      cb2->prev_cb = NULL;
    else
      *pSDU_CB_tail = NULL;

  }

pro_done:

  if (to_get == 0)
  {
    if (error_logged == 1)
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("processSDU:pro_done, to_get == 0, error_logged == 1, return 2\n");
#endif
      return 2;
    }
    else
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("processSDU:pro_done, to_get == 0, error_logged == 0, return 0\n");
#endif
      return 0;
    }
  }
  else
  {
    if (error_logged == 1)
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("processSDU:pro_done, to_get == 1, error_logged == 1, return 3\n");
#endif
      return 3;
    }
    else
    {
#ifdef __TCP_REASSEMBLE_LOG
      printf("processSDU:pro_done, to_get == 1, error_logged == 0, return 1\n");
#endif
      return 1;
    }
  }
}

TCPSduCb* cls_tcp_reassemble::allocate_cb(TCPSduCb *cb1, TCPSduCb *cb2,
    unsigned char *copy_from, unsigned int from_seq, unsigned int to_seq,
    unsigned int copy_len)
{
  TCPSduCb *cb3;

  if (copy_len < 0)
    return NULL;

  /*
  if (copy_len > 100000)
  {
  printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAA!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n\n");
  }
  */

  cb3 = (TCPSduCb*)malloc(sizeof(TCPSduCb));
  if (NULL==cb3)
  {
    printf("fail to allocate cb3!!!!!!\n");
    return NULL;
  }
  bzero(cb3, sizeof(TCPSduCb));
  memcpy(cb3->data_buf, copy_from, (copy_len > 1600)? 1600:copy_len);
  cb3->data_len = copy_len;
  cb3->start_seq = from_seq;
  cb3->end_seq = to_seq;
  cb3->prev_cb = cb1;
  cb3->next_cb = cb2;
  if (cb1 != NULL)
    cb1->next_cb = cb3;
  if (cb2 != NULL)
    cb2->prev_cb = cb3;
  return cb3;
}


void cls_tcp_reassemble::freeSDUcb(TCPSduCb** pSDU_CB_head)
{
  TCPSduCb *cb, *cb1;

  cb = *pSDU_CB_head;
  while(cb != NULL)
  {

    //      if(cb->data_len != 0)
    //              free(cb->data_buf);
    cb->data_len = 0;
    cb1 = cb->next_cb;
    free(cb);
    cb = cb1;
  }
}

//  end of the file

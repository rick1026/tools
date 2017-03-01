#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <zlib.h>
#include "http_reassemble.h"

#define __HTTP_REASSEMBLE_LOG




cls_reassemble::cls_reassemble ()
{
  if (sem_init (&sem_hash, 0, 1) == -1)
    {
      printf ("sem_init sem_hash error, exit!\n");
      exit (1);
    }

  if ((reassemble_tbl =
       create_hash (MAX_SIZE_TCP_HASH, tcp_sess_hash, tcp_sess_comp)) == NULL)
    {
      printf ("tcp_reassemble_init: create_hash error, exit!\n");
      exit (1);
    }

  printf ("cls_reassemble(): addr of tcp_reassemble_tbl = %p\n",
	  reassemble_tbl);

  pthread_create (&hdl_hash_timer_thr, NULL, reassemble_tbl_timer,
		  (void *) this);
}

cls_reassemble::~cls_reassemble ()
{
}

void* cls_reassemble::reassemble_tbl_timer(void *arg)
{
	cls_reassemble *pThis = reinterpret_cast<cls_reassemble*>(arg);

	pThis->do_timer();
}


}
char cls_reassemble::do_tcp_reassemble(unsigned int src_ip, unsigned int dst_ip,
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

  pBucket = find_hash(reassemble_tbl, &tcp_id);
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
        printf("process_tcp_packet: forward direction, call processSDU, forward_bytes=%u, init_forward_seq=%u,forward_min_seq=%u,forward_push_n
um=%u\n",
               p_tcp_session->forward_bytes, p_tcp_session->init_forward_seq, p_tcp_session->forward_min_seq, p_tcp_session->forward_push_num);
#endif
        ret_val = processSDU(pContent, content_len, &(p_tcp_session->forward_sdu_cb_head), &(p_tcp_session->forward_sdu_cb_tail),
                             data_buf, data_len, head, &(p_tcp_session->forward_bytes), p_tcp_session->init_forward_seq,
                             &(p_tcp_session->forward_min_seq), &(p_tcp_session->forward_push_num));
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: call processSDU return_val=%d, forward_bytes=%u, init_forward_seq=%u,forward_min_seq=%u,forward_push_num=%u
\n", ret_val,
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
        printf("process_tcp_packet: backward direction, call processSDU, backward_bytes=%u, init_backward_seq=%u,backward_min_seq=%u,backward_p
ush_num=%u\n",
               p_tcp_session->backward_bytes, p_tcp_session->init_backward_seq, p_tcp_session->backward_min_seq, p_tcp_session->backward_push_n
um);
#endif
        ret_val = processSDU(pContent, content_len,
                             &p_tcp_session->backward_sdu_cb_head, &p_tcp_session->backward_sdu_cb_tail,
                             data_buf, data_len, head, &p_tcp_session->backward_bytes, p_tcp_session->init_backward_seq,
                             &p_tcp_session->backward_min_seq, &p_tcp_session->backward_push_num);
#ifdef __TCP_REASSEMBLE_LOG
        printf("process_tcp_packet: call processSDU return_val=%d, backward_bytes=%u, init_backward_seq=%u,backward_min_seq=%u,backward_push_nu
m=%u\n", ret_val,
               p_tcp_session->backward_bytes, p_tcp_session->init_backward_seq, p_tcp_session->backward_min_seq, p_tcp_session->backward_push_n
um);
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

char cls_reassemble::processSDU(const unsigned char* pContent, unsigned int content_len,
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

TCPSduCb* cls_reassemble::allocate_cb(TCPSduCb *cb1, TCPSduCb *cb2,
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


void cls_reassemble::freeSDUcb(TCPSduCb** pSDU_CB_head)
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

 
#if 1
int cls_reassemble::ungzip(unsigned char *uncompr, unsigned int *uncompr_len, 
                                unsigned char *compr, unsigned int compr_len)
{
	int ret, have;
	int offset=0;
	z_stream d_stream;
	
	//一开始写成了comprlen=sizeof(compr)以及comprlen=strlen(compr)，后来发现都不对。
	//sizeof(compr)永远都是segment_size，显然不对，strlen(compr)也是不对的，因为strlen只算到\0之前，
	//但是gzip或者zlib数据里\0很多。
	d_stream.zalloc = Z_NULL;
	d_stream.zfree = Z_NULL;
	d_stream.opaque = Z_NULL;
	//d_stream.next_in = Z_NULL;
	d_stream.next_in = (Byte*)compr;
	d_stream.avail_in = 0;
	d_stream.next_out = (Byte*)uncompr;
	
	ret = inflateInit2(&d_stream, MAX_WBITS);
	if(ret!=Z_OK)
	{
   		printf("inflateInit2 error:%d",ret);
   		return ret;
	}
	
	d_stream.next_in = compr;
	d_stream.avail_in = compr_len;

	do
	{
 		d_stream.next_out = uncompr;
 		d_stream.avail_out = *uncompr_len;

 		ret = inflate(&d_stream,Z_NO_FLUSH);
 		if(ret == Z_STREAM_ERROR)
			return ret;

 		switch (ret)
 		{
  		case Z_NEED_DICT:
			ret = Z_DATA_ERROR;   
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
			(void)inflateEnd(&d_stream);
			return ret;
    	}


	}while(d_stream.avail_out==0);

	inflateEnd(&d_stream);
	*uncompr_len = d_stream.total_out;

	return ret;
}
#endif




unsigned int
http_sess_hash (void *key)
{
  int i;
  unsigned long ret = 0;

  for (i = 0; i < sizeof (TCPsessionID); i++)
    ret += *((unsigned char *) ((unsigned char *) key + i));

  unsigned int index = ret & MAX_INDEX_HTTP_HASH;
  //printf("http_sess_hash: index = %u\n", index);
  return index;
}

unsigned char
http_sess_comp (void *key1, void *key2)
{
  TCPsessionID *tcp_id1, *tcp_id2;

  if (!memcmp (key1, key2, sizeof (TCPsessionID)))
    {
      //printf("http_sess_comp: 111111111111\n");
      return 0;
    }

  tcp_id1 = (TCPsessionID *) key1;
  tcp_id2 = (TCPsessionID *) key2;
  if (tcp_id1->src_ip == tcp_id2->dst_ip &&
      tcp_id1->dst_ip == tcp_id2->src_ip &&
      tcp_id1->src_port == tcp_id2->dst_port &&
      tcp_id1->dst_port == tcp_id2->src_port)
    {
      return 0;
    }

  return 1;
}

char
cls_reassemble::FreeHttpHashNode (TCPsessionID sess_id)
{

  hash_bucket *pBucket = find_hash (http_reassemble_tbl, &sess_id);
  if (pBucket != NULL)
    {
      stru_http_info *http_obj = (stru_http_info *) (pBucket->content);
      free_list (&(http_obj->sdu_list_up));	// 清空当前的所有已缓存数据
      free_list (&(http_obj->sdu_list_down));
      free (pBucket->content);
      free (pBucket);
    }
  return 0;
}

cls_reassemble::cls_reassemble ()
{
  if (sem_init (&sem_http_hash, 0, 1) == -1)
    {
      printf ("cls_reassemble: sem_init(sem_http_hash) error, exit!\n");
      exit (1);
    }

  if ((http_reassemble_tbl =
       create_hash (MAX_SIZE_HTTP_HASH, http_sess_hash,
		    http_sess_comp)) == NULL)
    {
      printf
	("cls_reassemble: create_hash(http_reassemble_tbl) error, exit!\n");
      exit (1);
    }
  printf ("cls_reassemble(): addr of http_reassemble_tbl = %p\n",
	  http_reassemble_tbl);

  pthread_create (&hdl_http_hash_timer, NULL, http_cache_tbl_timer,
		  (void *) this);
}

cls_reassemble::~cls_reassemble ()
{
}


void
cls_reassemble::do_timer ()
{
  while (1)
    {
      sleep (5);
      printf
	("%u, cls_reassemble do_timer() running, addr of http_reassemble_tbl = %p!!!\n",
	 time (0), http_reassemble_tbl);

    }

}

char
cls_reassemble::do_http_reassemble (TCPsessionID sess_id,
					 unsigned int sdu_len,
					 unsigned char *sdu_data,
					 stru_http_req_head * http_header,
					 enum TCPDirection dir,
					 unsigned int *http_data_len,
					 unsigned char **http_data_buf,
					 int *http_type)
{
#ifdef __HTTP_REASSEMBLE_LOG
  printf ("do_http_reassemble: addr of http_reassemble = %p\n",
	  http_reassemble_tbl);
  printf
    ("do_http_reassemble: proto: %d, sip:%u, dip %u, sport:%d, dport:%d\n",
     sess_id.proto, sess_id.src_ip, sess_id.dst_ip, sess_id.src_port,
     sess_id.dst_port);
#endif
  hash_bucket *pBucket = find_hash (http_reassemble_tbl, &sess_id);

  char http_errno = 0;
  stru_http_info *http_obj = NULL;

  char to_get = 0;
  unsigned char *http_data = NULL;

  stru_http_req_head temp_head;
  bzero (&temp_head, sizeof (temp_head));


  if (pBucket == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("do_http_reassemble: find_hash == NULL, method = %d\n",
	      http_header->method);
#endif
      // 若一个新HTTP连接的第一个SDU不是HTTP请求,则直接跳过当前SDU
      // 不能忽略对这条连接的后续SDU处理,因为一个连接上可能有多个HTTP请求,其中
      // 一个的数据丢失,不代表后续请求的数据也会丢失.

      // 对于新连接的第一个请求,认为其SDU中一定包含完整的http头部,若不包含,则认为错误,直接返回
      // 对于GET报文这种假设应该是成立的,但对于POST报文是否一定成立暂不确定,从实际的报文分析结果看
      // 都是符合这一假设的,若后续发现有特殊情况,再根据情况进行修订.
      // 这一假设的成立是由TCP重组来保证的.虽然TCP重组内部并未刻意处理以确保此事,但这里
      // 我们根据TCP协议的特性认为只要是经过TCP重组后,就一定是符合这一情况的.
      if (!(http_header->method == 1 || http_header->method == 2))
	{
#ifdef __HTTP_REASSEMBLE_LOG
	  printf ("process_http: the first SDU is not a http req, error\n");
#endif
	  http_errno = 1;
	  free (sdu_data);	// added on 20150810

	  goto LABEL_SEM_POST;
	}

      // 如果HTTP REQ不完整,解析出错,则错误返回
      if (analyse_http_req (sdu_data, sdu_len, &temp_head))
	{
#ifdef __HTTP_REASSEMBLE_LOG
	  printf ("process_http: analyse_http_req error\n");
#endif
	  http_errno = 1;
	  free (sdu_data);	// added on 20150810
	  goto LABEL_SEM_POST;
	}

      http_obj = (stru_http_info *) calloc (1, sizeof (stru_http_info));
      http_obj->sessid = sess_id;
      http_obj->method = temp_head.method;
      http_obj->status =
	temp_head.tailer_bingo ? (S_REQ_HEAD_END) : (S_REQ_HEAD_START);
      http_obj->req_head_len = temp_head.head_len;
      http_obj->req_body_len = temp_head.content_len;
      http_obj->req_got_len = sdu_len;

      if (temp_head.url[0] != '\0')
	strncpy (http_obj->url, temp_head.url, sizeof (http_obj->url));
      if (temp_head.host[0] != '\0')
	strncpy (http_obj->host, temp_head.host, sizeof (http_obj->host));
      if (temp_head.content_type[0] != '\0')
	strncpy (http_obj->content_type, temp_head.content_type,
		 sizeof (http_obj->content_type));

#ifdef __HTTP_REASSEMBLE_LOG
      printf ("do_http_reassemble: find_hash==NULL, get req infO, \
                status = %d, req_head_len = %d, req_body_len = %d, req_got_len = %d\n", http_obj->status, http_obj->req_head_len, http_obj->req_body_len, http_obj->req_got_len);
#endif

      insert_list (&(http_obj->sdu_list_up), sdu_data, sdu_len);

      pBucket = (hash_bucket *) calloc (1, sizeof (hash_bucket));
      pBucket->key = &(http_obj->sessid);
      pBucket->content = (void *) http_obj;
      insert_hash (http_reassemble_tbl, pBucket);
    }
  // 对于既有连接的处理,这里比新连接的处理要复杂的多,需要考虑很多种情况
  // 对于HTTP RESP消息,一定会在这个分支中处理
  else
    {
#ifdef __HTTP_REASSEMBLE_LOG
      printf
	("do_http_reassemble: find_hash != NULL, http_header->method = %d........\n",
	 http_header->method);
#endif
      // 这里的要处理的情况包括:
      // (1) 一个POST请求报文的BODY及其后续部分,此时http_status==REQ_HEAD_END
      // (2) 一个GET请求的全部内容或一个POST请求的完整头部,此时http_status==RESP_END
      // (3) 一个response回应的完整头部此时http_status==REQ_END
      // (4) 一个response回应的BODY及其后续部分,此时http_status==RESP_HEAD_END
      // (5) 一个response回应的完整内容,此时http_status==REQ_END
      http_obj = (stru_http_info *) (pBucket->content);

#ifdef __HTTP_REASSEMBLE_LOG
      printf
	("do_http_reassemble: find_hash != NULL, http_info, status = %d\n",
	 http_obj->status);
#endif

      // 如果是一个已经存在的连接,且当前收到了一个新的HTTP REQ, 说明此前的HTTP数据发生丢失,
      // 此时,将此前的所有缓存数据清空(如果保留该怎么处理????),重新缓存当前REQ对应的数据

      // 对于从CLIENT发往SERVER端的数据,若不是新的HTTP_REQ,那么只有在当前状态为S_REQ_HEAD_START/
      // S_REQ_HEAD_END/S_RSP_END的情况下才应该处理
      if (dir == FROM_CLIENT)
	{
#ifdef __HTTP_REASSEMBLE_LOG
	  printf
	    ("do_http_reassemble: find_hash!=NULL, dir== FROM_CLIENT.....\n");
#endif
	  if (http_header->method == 1 || http_header->method == 2)
	    {
#ifdef __HTTP_REASSEMBLE_LOG
	      printf
		("dir==FROM_CLIENT, a new http_req, clear all the old data in link_list\n");
#endif
	      free_list (&(http_obj->sdu_list_up));	// 清空当前的所有已缓存数据
	      free_list (&(http_obj->sdu_list_down));

	      if (analyse_http_req (sdu_data, sdu_len, &temp_head))
		{
#ifdef __HTTP_REASSEMBLE_LOG
		  printf ("process_http: analyse_http_req error\n");
#endif
		  http_errno = 1;
		  free (sdu_data);	// added on 20150810
		  goto LABEL_SEM_POST;
		}

	      bzero (http_obj, sizeof (stru_http_info));
	      http_obj->sessid = sess_id;
	      http_obj->method = temp_head.method;
	      http_obj->status =
		temp_head.
		tailer_bingo ? (S_REQ_HEAD_END) : (S_REQ_HEAD_START);
	      http_obj->req_head_len = temp_head.head_len;
	      http_obj->req_body_len = temp_head.content_len;
	      //http_obj->req_got_len = sdu_len;

	      if (temp_head.url[0] != '\0')
		strncpy (http_obj->url, temp_head.url,
			 sizeof (http_obj->url));
	      if (temp_head.host[0] != '\0')
		strncpy (http_obj->host, temp_head.host,
			 sizeof (http_obj->host));
	      if (temp_head.content_type[0] != '\0')
		strncpy (http_obj->content_type, temp_head.content_type,
			 sizeof (http_obj->content_type));

#ifdef __HTTP_REASSEMBLE_LOG
	      printf
		("dir==FROM_CLIENT, analyse_http_req, method = %d, status = %d, \
                       req_head_len = %d, req_body_len = %d, req_got_len = %d\n",
		 http_obj->method, http_obj->status, http_obj->req_head_len, http_obj->req_body_len, http_obj->
		 req_got_len);
#endif

	      //insert_list(&(http_obj->sdu_list_up), sdu_data, sdu_len);
	    }
	  else
	    {
	      if (!(http_obj->status == S_RSP_END ||
		    http_obj->status == S_REQ_HEAD_END
		    || http_obj->status == S_REQ_HEAD_START))
		{
#ifdef __HTTP_REASSEMBLE_LOG
		  printf
		    ("dir==DIR_CLIENT, recv a up_data in the wrong status, goto LABEL_SEM_POST\n");
#endif
		  http_errno = 1;
		  free (sdu_data);	// added on 20150810
		  goto LABEL_SEM_POST;
		}
	    }

	  insert_list (&(http_obj->sdu_list_up), sdu_data, sdu_len);
	  http_obj->req_got_len += sdu_len;
#ifdef __HTTP_REASSEMBLE_LOG
	  printf
	    ("dir==FROM_CLIENT, save the sdu_data in sdu_list_up, req_got_len = %d\n",
	     http_obj->req_got_len);
#endif
	}
      // 对于从SERVER端发往CLIENT的数据,只有在当前状态为S_REQ_END/S_RSP_HEAD_END的情况下才应该处理
      else if (dir == FROM_SERVER)
	{
	  if (!
	      (http_obj->status == S_REQ_END
	       || http_obj->status == S_RSP_HEAD_END))
	    {
#ifdef __HTTP_REASSEMBLE_LOG
	      printf
		("dir==FROM_SERVER, recv a down_data in the wrong status, goto LABEL_SEM_POST\n");
#endif
	      http_errno = 1;
	      free (sdu_data);	// added on 20150810
	      goto LABEL_SEM_POST;
	    }

	  // 这里,要判断当前SDU是否是HTTP RSP的第一个数据单元,若是的话,要从中解析出相应的信息.比如:
	  // content-type/transfer-encoding/content-encoding等字段内容
	  bzero (&temp_head, sizeof (temp_head));
	  if (analyse_http_resp (sdu_data, sdu_len, &temp_head))
	    {
#ifdef __HTTP_REASSEMBLE_LOG
	      printf ("process_http: analyse_http_resp error\n");
#endif
	      http_errno = 1;
	      free (sdu_data);	// added on 20150810
	      goto LABEL_SEM_POST;
	    }

	  if (temp_head.method == method_resp)
	    {
#ifdef __HTTP_REASSEMBLE_LOG
	      printf
		("dir==FROM_SERVER, a new http resp, clear the old data in link_list\n");
#endif
	      free_list (&http_obj->sdu_list_down);

	      http_obj->status = S_RSP_HEAD_END;
	      http_obj->rsp_chunk_flag = temp_head.chunk_flag;
	      http_obj->rsp_gzip_flag = temp_head.gzip_flag;
	      http_obj->rsp_head_len = temp_head.head_len;
	      http_obj->rsp_body_len = temp_head.content_len;
	      http_obj->type_text_flag = temp_head.type_text_flag;
	      strncpy (http_obj->content_type, temp_head.content_type,
		       sizeof (temp_head.content_type));

#ifdef __HTTP_REASSEMBLE_LOG
	      printf
		("a new http resp, http_info, status = %d, url = %s, host = %s, rsp_chunk_flag = %d, \
                        rsp_gzip_flag = %d, rsp_head_len = %d, rsp_body_len = %d\n",
		 http_obj->status, http_obj->url, http_obj->host, http_obj->rsp_chunk_flag, http_obj->rsp_gzip_flag, http_obj->rsp_head_len,
		 http_obj->rsp_body_len);
#endif
	    }

	  insert_list (&(http_obj->sdu_list_down), sdu_data, sdu_len);
	  http_obj->rsp_got_len += sdu_len;

#ifdef __HTTP_REASSEMBLE_LOG
	  printf
	    ("dir==FROM_SERVER, save the sdu_data in sdu_list_down, rsp_got_len = %d\n",
	     http_obj->rsp_got_len);
#endif
	}

      switch (http_obj->status)
	{
	}
    }

#ifdef __HTTP_REASSEMBLE_LOG
  printf ("http_obj->status = %d\n", http_obj->status);
#endif

  // 接下来根据hash表中的http_obj的status来决定当前需要重组返回的是完整的http req还是http resp.
  // 若是http_req,则根据req_len和req_got_len来判断REQ是否完整
  // 若是http_resp,则根据resp_len和resp_got_len来判断RESP是否完整.对于chunk的RESP,则需要
  // 根据chunk_tailer来判断RESP是否完整

  to_get = 0;
  switch (http_obj->status)
    {
    case S_REQ_HEAD_START:
      to_get = 0;
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("process_http: case S_REQ_HEAD_START, break.........\n");
#endif
      break;
    case S_REQ_HEAD_END:
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("process_http: case S_REQ_HEAD_END, go on doing.........\n");
#endif
      // 若http req头部结束,则判断req_got_len与req_len是否相等,
      // 对于GET请求,两个应该相等,
      // 这时便可以取出链表上的数据作为完整的GET请求返回.对于POST请求,
      // 若两个也相等,则POST请求
      // 也完整,取出链表数据作为完整POST请求返回.若是POST请求但两个长度
      // 不相等,则等待后续的POST
      // BODY部分数据.处理完成之后更新其http_status的状态为S_REQ_END
      // 注意:要处理在一个SDU中包含了REQ_HEAD的结束以及
      // BODY部分若干数据的情况
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("req_got_len = %d, req_head_len = %d, req_body_len = %d\n",
	      http_obj->req_got_len, http_obj->req_head_len,
	      http_obj->req_body_len);
#endif
      if (http_obj->req_got_len >=
	  (http_obj->req_head_len + http_obj->req_body_len))
	{
	  to_get = 1;
	  http_data =
	    (unsigned char *) calloc (http_obj->req_got_len,
				      sizeof (unsigned char));
	  *http_data_len = http_obj->req_got_len;
	  get_list_data (http_obj->sdu_list_up, http_data);
	  free_list (&(http_obj->sdu_list_up));
	  free_list (&(http_obj->sdu_list_down));
	  http_obj->status = S_REQ_END;
	  //printf("set http_obj->status = %d\n", S_REQ_END);
	  *http_type = 1;

	}
      else
	to_get = 0;
      break;
    case S_REQ_END:
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("process_http: case S_REQ_END, break.........\n");
#endif
      break;
    case S_RSP_HEAD_START:
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("process_http: case S_RSP_HEAD_START, break.........\n");
#endif
      break;
    case S_RSP_HEAD_END:
      // 对于HTTP RESP的结束判断,不能像REQ一样只根据got_len进行.要区分是否有chunk分块.对于没有chunk分块的
      // RESP,根据got_len判断即可.但对于做了chunk分块的response,需要在当前SDU中查找chunk_tailer来判定
      // 当前http response是否已经结束.
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("process_http: case S_RSP_HEAD_END, go on dong......\n");
      printf ("rsp_got_len = %d, rsp_head_len = %d, rsp_body_len = %d\n",
	      http_obj->rsp_got_len, http_obj->rsp_head_len,
	      http_obj->rsp_body_len);
#endif
      if ((http_obj->rsp_chunk_flag == 0)
	  && (http_obj->rsp_got_len >=
	      (http_obj->rsp_head_len + http_obj->rsp_body_len)))
	{
#ifdef __HTTP_REASSEMBLE_LOG
	  printf ("http resp not chunk, set to_get == 1\n");
#endif
	  to_get = 1;
	}
      else if (http_obj->rsp_chunk_flag)
	{
	  if ((sdu_len >= 5)
	      && !memcmp (sdu_data + sdu_len - 5, "0\r\n\r\n", 5))
	    {
#ifdef __HTTP_REASSEMBLE_LOG
	      printf
		("http resp with chunk, find chunk tailer, set to_get == 1\n");
#endif
	      to_get = 1;
	    }
	  else if ((sdu_len == 2) && !memcmp (sdu_data, "\r\n", 2))
	    {
	      to_get = 1;
	    }
	  else
	    to_get = 0;
	}
      else
	{
	  to_get = 0;
#ifdef __HTTP_REASSEMBLE_LOG
	  printf ("http resp, set to_get==0\n");
#endif
	}
      if (to_get == 1)
	{
	  *http_type = 3;
	  http_data =
	    (unsigned char *) calloc (http_obj->rsp_got_len,
				      sizeof (unsigned char));
	  *http_data_len = http_obj->rsp_got_len;
	  get_list_data (http_obj->sdu_list_down, http_data);
	  free_list (&(http_obj->sdu_list_up));
	  free_list (&(http_obj->sdu_list_down));
	  http_obj->status = S_RSP_END;
#ifdef __HTTP_REASSEMBLE_LOG
	  printf ("to_get == 1, set http_obj->status = %d\n", S_RSP_END);
#endif

	  http_header->gzip_flag = http_obj->rsp_chunk_flag;
	  http_header->chunk_flag = http_obj->rsp_chunk_flag;
	  http_header->type_text_flag = http_obj->type_text_flag;
	}
      break;
    case S_RSP_END:
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("process_http: case S_RSP_END, break.........\n");
#endif
      break;
    default:
      break;
    }


LABEL_SEM_POST:
  sem_post (&sem_http_hash);

  if (to_get == 1)
    {
      *http_data_buf = http_data;
      return 0;
    }
  else
    {
      return 1;
    }

  //return http_errno;
}

inline int
cls_reassemble::insert_list (stru_tcpsdu_node ** head,
				  unsigned char *data, int data_len)
{
  if (data_len <= 0)
    return 0;

  stru_tcpsdu_node *temp = NULL;
  stru_tcpsdu_node *new_Bucket =
    (stru_tcpsdu_node *) malloc (sizeof (stru_tcpsdu_node));
  bzero (new_Bucket, sizeof (stru_tcpsdu_node));

#if 0				// modified on 20150810
  new_Bucket->data = (unsigned char *) malloc (data_len + 1);
  bzero (new_Bucket->data, data_len + 1);
  memcpy (new_Bucket->data, data, data_len);
#endif

  new_Bucket->data = data;
  new_Bucket->data_len = data_len;
  new_Bucket->next = NULL;

  //printf("insert_list: addr of new node: %p\n", new_Bucket);

  if (*head == NULL)
    {
      *head = new_Bucket;
    }
  else
    {
      temp = *head;
      while (temp->next != NULL)
	{
	  temp = temp->next;
	}
      temp->next = new_Bucket;
    }
}

inline int
cls_reassemble::get_list_data (stru_tcpsdu_node * head,
				    unsigned char *data)
{
  int pos = 0;
  while (head != NULL)
    {
      memcpy (data + pos, head->data, head->data_len);
      pos += head->data_len;
      head = head->next;
    }
  return 0;
}

inline int
cls_reassemble::free_list (stru_tcpsdu_node ** head)
{
  if (head == NULL || *head == NULL)
    return 0;

  //printf("free_list: addr of list: %p, addr of first node: %p\n", head, *head);

  stru_tcpsdu_node *cur = (*head);
  stru_tcpsdu_node *next = (*head)->next;
  while (cur != NULL)
    {
      next = cur->next;
      if (cur->data != NULL)
	{
	  free (cur->data);
	  cur->data = NULL;
	}
      free (cur);
      cur = next;
    }

  *head = NULL;
}

char
cls_reassemble::analyse_http_req (unsigned char *data,
				       unsigned int datalen,
				       stru_http_req_head * header)
{
  // 缓冲区为空或者长度过小,错误返回
  if (data == NULL || datalen < 20)
    return 1;

  unsigned char *p_url_start = NULL, *p_url_end = NULL;
  if (memcmp (data, "GET ", 4) == 0)
    {
      header->method = method_get;
      p_url_start = data + 4;
    }
  else if (memcmp (data, "POST ", 5) == 0)
    {
      header->method = method_post;
      p_url_start = data + 5;
    }
  else
    return 1;

  // the request packet doesn't contain \n, return
  unsigned char *p_head_tailer =
    (unsigned char *) memmem (data, datalen, "\n", 1);
  if (p_head_tailer == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("can't 2222222222 tailer!!!!\n");
#endif
      return 1;
    }
  int find_len = p_head_tailer - data;
#ifdef __HTTP_REASSEMBLE_LOG
  printf ("datalen = %d, find_len = %d\n", datalen, find_len);
#endif

  // get the http version
  unsigned char *p_http_ver =
    (unsigned char *) memmem (data, find_len, "HTTP", 4);
  if (p_http_ver == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("can't 3333333333 HTTP!!!!\n");
#endif
      return 1;
    }

  p_url_end = (*(p_http_ver - 1) = ' ') ? (p_http_ver - 1) : (p_http_ver);

  unsigned char url[256];
  bzero (url, sizeof (url));
  int copy_len = p_url_end - p_url_start;
  if (copy_len >= sizeof (url))
    copy_len = sizeof (url) - 1;

  //memcpy(url, p_url_start, p_url_end - p_url_start);
  memcpy (url, p_url_start, copy_len);
#ifdef __HTTP_REASSEMBLE_LOG
  printf ("get_http_req_head: url = <%s>\n", url);
#endif
  strncpy (header->url, (const char *) url, sizeof (url) - 1);

  // the request packet doesn't contain Host header, return
  unsigned char *p_host =
    (unsigned char *) memmem (data, datalen, "Host: ", 6);
  if (p_host == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("44444444444 HOST error!!!!\n");
#endif
      return 1;
    }

  p_head_tailer =
    (unsigned char *) memmem (p_host, datalen - (p_host - data), "\n", 1);
  if (p_head_tailer == NULL)
    {
      return 1;
    }

  unsigned char host[256];
  bzero (host, sizeof (host));
  if (*(p_head_tailer - 1) == '\r')
    p_head_tailer--;

  memcpy (host, p_host + 6, p_head_tailer - p_host - 6);
#ifdef __HTTP_REASSEMBLE_LOG
  printf ("get_http_req_head: host = <%s>\n", host);
#endif
  strcpy (header->host, (const char *) host);

  if (header->method == method_post)
    {
      unsigned char *p_len =
	(unsigned char *) memmem (data, datalen, "Content-Length: ", 16);
      if (p_len != NULL)
	{
	  p_head_tailer =
	    (unsigned char *) memmem (p_len, datalen - (p_len - data), "\n",
				      1);
	  if (p_head_tailer != NULL)
	    {
	      if (*(p_head_tailer - 1) == '\r')
		p_head_tailer--;

	      unsigned char len[16];
	      bzero (len, sizeof (len));
	      memcpy (len, p_len + 16, p_head_tailer - p_len - 16);
	      header->content_len = atoi ((const char *) len);
#ifdef __HTTP_REASSEMBLE_LOG
	      printf ("http post req, get content_len = %d\n",
		      header->content_len);
#endif
	    }
	}

      unsigned char *p_type =
	(unsigned char *) memmem (data, datalen, "Content-Type: ", 14);
      if (p_type != NULL)
	{
	  p_head_tailer =
	    (unsigned char *) memmem (p_type, datalen - (p_type - data), "\n",
				      1);
	  if (p_head_tailer != NULL)
	    {
	      if (*(p_head_tailer - 1) == '\r')
		p_head_tailer--;

	      memcpy (header->content_type, p_type + 14,
		      p_head_tailer - p_type - 14);
#ifdef __HTTP_REASSEMBLE_LOG
	      printf ("http post req, get content-type = %s\n",
		      header->content_type);
#endif

	      if ((strstr ((const char *) (header->content_type), "text/html")
		   != NULL)
		  ||
		  (strstr
		   ((const char *) (header->content_type),
		    "text/javascript") != NULL)
		  ||
		  (strstr
		   ((const char *) (header->content_type),
		    "application/x-gzip") != NULL)
		  ||
		  (strstr
		   ((const char *) (header->content_type),
		    "application/x-msgpack") != NULL))
		header->type_text_flag = 1;
	      else
		header->type_text_flag = 0;
	    }
	}
    }

  // the request need tcp_reassemble, return
  if ((p_head_tailer =
       (unsigned char *) memmem (data, datalen, "\r\n\r\n", 4)) != NULL)
    {
      header->head_len = p_head_tailer - data + 4;
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("http req, get head_len = %d\n", header->head_len);
#endif
      header->tailer_bingo = 1;

      if (header->method == method_get)
	{
	  header->content_len = 0;
	  //header->content_len = datalen = header->head_len;
	}
    }
  else
    return 1;

  return 0;
}

char
cls_reassemble::analyse_http_resp (unsigned char *data,
					unsigned int datalen,
					stru_http_req_head * header)
{
  // 缓冲区为空或者长度过小,错误返回
  if (data == NULL || datalen < 0)
    return 1;

  if (datalen < 5)
    return 0;


  if (memcmp (data, "HTTP/", 5))
    {
      return 0;
    }

  unsigned char *p_head_tailer =
    (unsigned char *) memmem (data, datalen, "\r\n\r\n", 4);
  if (p_head_tailer == NULL)
    {
      return 1;
    }

  header->method = method_resp;
  header->head_len = p_head_tailer - data + 4;

  p_head_tailer = (unsigned char *) memmem (data, datalen, "\n", 1);
  if (p_head_tailer == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("can't 2222222222 tailer!!!!\n");
#endif
      return 1;
    }

  if (datalen < 14)
    return 1;

  unsigned char *p_type =
    (unsigned char *) memmem (data, datalen, "Content-Type: ", 14);
  if (p_type != NULL)
    {
      p_head_tailer =
	(unsigned char *) memmem (p_type, datalen - (p_type - data), "\n", 1);
      if (p_head_tailer != NULL)
	{
	  if (*(p_head_tailer - 1) == '\r')
	    p_head_tailer--;

	  memcpy (header->content_type, p_type + 14,
		  p_head_tailer - p_type - 14);
#ifdef __HTTP_REASSEMBLE_LOG
	  printf ("http response, get content-type = %s\n",
		  header->content_type);
#endif
	  if ((strstr ((const char *) (header->content_type), "text/html") !=
	       NULL)
	      ||
	      (strstr
	       ((const char *) (header->content_type),
		"text/javascript") != NULL)
	      ||
	      (strstr
	       ((const char *) (header->content_type),
		"application/x-gzip") != NULL)
	      ||
	      (strstr
	       ((const char *) (header->content_type),
		"application/x-msgpack") != NULL))
	    header->type_text_flag = 1;
	  else
	    header->type_text_flag = 0;
	}
    }

  unsigned char *p_len =
    (unsigned char *) memmem (data, datalen, "Content-Length: ", 16);
  if (p_len != NULL)
    {
      p_head_tailer =
	(unsigned char *) memmem (p_len, datalen - (p_len - data), "\n", 1);
      if (p_head_tailer != NULL)
	{
	  if (*(p_head_tailer - 1) == '\r')
	    p_head_tailer--;

	  unsigned char len[16];
	  bzero (len, sizeof (len));
	  memcpy (len, p_len + 16, p_head_tailer - p_len - 16);
	  header->content_len = atoi ((const char *) len);
#ifdef __HTTP_REASSEMBLE_LOG
	  printf ("http response, get content_len = %d\n",
		  header->content_len);
#endif
	}
    }

  unsigned char *p_trancode =
    (unsigned char *) memmem (data, datalen, "Transfer-Encoding: ", 19);
  if (p_trancode != NULL)
    {
      p_head_tailer =
	(unsigned char *) memmem (p_trancode,
				  datalen - (unsigned int) (p_trancode -
							    data), "\n", 1);
      if (p_head_tailer != NULL)
	{
	  if (*(p_head_tailer - 1) == '\r')
	    p_head_tailer--;

	  header->chunk_flag = 1;
#ifdef __HTTP_REASSEMBLE_LOG
	  printf ("http response, get chunk_flag =1 \n");
#endif
	}
    }

  unsigned char *p_contcode =
    (unsigned char *) memmem (data, datalen, "Content-Encoding: ", 18);
  if (p_contcode != NULL)
    {
      p_head_tailer =
	(unsigned char *) memmem (p_contcode, datalen - (p_contcode - data),
				  "\n", 1);
      if (p_head_tailer != NULL)
	{
	  if (*(p_head_tailer - 1) == '\r')
	    p_head_tailer--;

	  unsigned char cont_coding[32];
	  bzero (cont_coding, sizeof (cont_coding));
	  memcpy (cont_coding, p_contcode + 18,
		  p_head_tailer - p_contcode - 18);
#ifdef __HTTP_REASSEMBLE_LOG
	  printf ("http response, get content-encoding: (%s)\n", cont_coding);
#endif
	  header->gzip_flag = 1;
	}
    }

  return 0;
}

int
cls_reassemble::dechunk_data (unsigned char *data,
				   unsigned int *data_len)
{
  unsigned char *pos_head_end = NULL;
  unsigned char *pos_body_start = NULL;
  unsigned char *pos_chunk_tailer = NULL;
  unsigned char *pos_chunk_size_end = NULL;
  unsigned char *pos_chunk_data_begin = NULL;
  unsigned char chunk_tailer[] = "0\r\n";
  unsigned char http_head_end[] = "\r\n\r\n";
  unsigned char chunk_size_end[] = "\r\n";
  unsigned char chunk_data_end[] = "\r\n";

  int i = 0;
  int j = 0;
  int http_head_end_len = sizeof (http_head_end) - 1;
  int chunk_tailer_len = sizeof (chunk_tailer) - 1;
  int chunk_size_end_len = sizeof (chunk_size_end) - 1;
  int chunk_data_end_len = sizeof (chunk_size_end) - 1;
  int chunk_size_len = 0;
  int chunk_data_len = 0;
  int header_len = 0, body_len = 0;

  int cache_len = *data_len;
  unsigned char *cache_data = (unsigned char *) malloc (cache_len);
  bzero (cache_data, cache_len);
  memcpy (cache_data, data, cache_len);
#ifdef __HTTP_REASSEMBLE_LOG
  printf
    ("dechunk_data: http_head_end_len = %d, chunk_tailer_len = %d, chunk_size_end_len = %d\n",
     http_head_end_len, chunk_tailer_len, chunk_size_end_len);
  printf
    ("dechunk_data: cache_len = %d, cache_data's content is as follows:\n",
     cache_len);
#endif

#if 0
  for (i = 0; i < cache_len; i++)
    {
      printf ("%02X ", cache_data[i]);
      j++;
      if (j % 8 == 0)
	printf ("  ");
      if (j % 16 == 0)
	printf ("\n");
    }
  printf ("\n");
#endif

  if ((pos_head_end =
       (unsigned char *) memmem (cache_data, cache_len, http_head_end,
				 http_head_end_len)) == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
      printf
	("dechunk_data: there is no http_header_end, error and return -1!!!\n");
#endif
      free (cache_data);
      cache_data = NULL;
      return -1;
    }

  pos_body_start = pos_head_end + http_head_end_len;
  header_len = pos_body_start - cache_data;
  body_len = cache_len - header_len;

#ifdef __HTTP_REASSEMBLE_LOG
  printf
    ("dechunk_data: check http header pass, header_len = %d, chunked body_len = %d, go on dechunk\n",
     header_len, body_len);
#endif

  if ((pos_chunk_tailer =
       (unsigned char *) memmem (pos_body_start, body_len, chunk_tailer,
				 chunk_tailer_len)) == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
      printf
	("dechunk_data: there is no chunk_tailer, error and return -1!!!\n");
#endif
      free (cache_data);
      cache_data = NULL;
      return -1;
    }

  // clear data buf to save dechunked data
  bzero (data, *data_len);
  *data_len = 0;

  // get the chunked http body data and dechunked it, first copy the http_header to dechunked data buf
  unsigned char *pos_copy_begin = data;
  int copy_len = header_len;
  memcpy (pos_copy_begin, cache_data, copy_len);
  pos_copy_begin += copy_len;
  *data_len += copy_len;

#ifdef __HTTP_REASSEMBLE_LOG
  printf
    ("dechunk_data: check chunk_tailer pass, first copy http_header, header_len = %d, have copyed_len = %d, then go on processing!!\n",
     copy_len, *data_len);
#endif

  // second: get the chunked data's length, only copy the chunked data to dechunked data buf, do util the tailer chunked data
  unsigned char str_chunk_size[16];
  int str_chunk_size_len = 0;
  unsigned char *chunked_data_begin = pos_body_start;
  int chunked_data_len = body_len;
  pos_chunk_size_end =
    (unsigned char *) memmem (chunked_data_begin, chunked_data_len,
			      chunk_size_end, chunk_size_end_len);

  int dechunked_data_len = 0;

#ifdef __HTTP_REASSEMBLE_LOG
  printf
    ("dechunk_data: dechunk the http_body, length of data to be dechunked = %d\n",
     chunked_data_len);
#endif


  // get every chunked data's length and dechunk it
  while (pos_chunk_size_end != NULL)
    {
      bzero (str_chunk_size, sizeof (str_chunk_size));
      str_chunk_size_len = pos_chunk_size_end - chunked_data_begin;
      memcpy (str_chunk_size, chunked_data_begin, str_chunk_size_len);
      copy_len = atox ((char *) str_chunk_size);

      if (copy_len == -1)
	{
	  free (cache_data);
	  cache_data = NULL;
	  return -1;
	  break;
	}

#ifdef __HTTP_REASSEMBLE_LOG
      printf
	("dechunk_data, get sting of chunk size: %s, chunk_len = copy_len = %d\n",
	 str_chunk_size, copy_len);
#endif

      if (copy_len == 0)
	break;
      bzero (str_chunk_size, sizeof (str_chunk_size));
      str_chunk_size_len = pos_chunk_size_end - chunked_data_begin;
      memcpy (str_chunk_size, chunked_data_begin, str_chunk_size_len);
      copy_len = atox ((char *) str_chunk_size);

      if (copy_len == -1)
	{
	  free (cache_data);
	  cache_data = NULL;
	  return -1;
	  break;
	}

#ifdef __HTTP_REASSEMBLE_LOG
      printf
	("dechunk_data, get sting of chunk size: %s, chunk_len = copy_len = %d\n",
	 str_chunk_size, copy_len);
#endif

      if (copy_len == 0)
	break;

      // copy to data and set the new copy_position
      dechunked_data_len += copy_len;
      *data_len += copy_len;

      if (*data_len >= cache_len)
	{
	  free (cache_data);
	  cache_data = NULL;
	  return -1;
	}
      memcpy (pos_copy_begin, pos_chunk_size_end + chunk_size_end_len,
	      copy_len);
      pos_copy_begin += copy_len;

      //printf("dechunked_data: copy_len > 0, copy to destination\n");

      // locate the begin position of the next chunked data
      chunked_data_begin =
	pos_chunk_size_end + chunk_size_end_len + copy_len +
	chunk_size_end_len;
      chunked_data_len =
	chunked_data_len - (str_chunk_size_len + chunk_size_end_len +
			    copy_len + chunk_data_end_len);
      pos_chunk_size_end =
	(unsigned char *) memmem (chunked_data_begin, chunked_data_len,
				  chunk_size_end, chunk_size_end_len);

#ifdef __HTTP_REASSEMBLE_LOG
      printf
	("dechunk_data, copy chunked data, copy_len = %d, dechunked_data_len = %d, to be dechunked_len = %d\n",
	 copy_len, dechunked_data_len, chunked_data_len);
#endif
    }

#if 0
  printf ("dechunk_data: dechunked_data_len = %d, content is as follows:\n",
	  dechunked_data_len);
  for (i = 0; i < dechunked_data_len; i++)
    {
      printf ("%02X ", *(data + header_len + i));
      j++;
      if (j % 8 == 0)
	printf ("  ");
      if (j % 16 == 0)
	printf ("\n");
    }
  printf ("\n");

#endif

  free (cache_data);
  cache_data = NULL;

  return 0;
}

int
cls_reassemble::unzip_data (unsigned char *data, unsigned int data_len,
				 unsigned char **unzip_buf,
				 unsigned int *unzip_len)
{
  unsigned char *pMem = NULL;
  unsigned char *p = NULL, *q = NULL, *content_start = NULL;
  char pLength[128];
  unsigned int zipped_length = 0;

#ifdef __HTTP_REASSEMBLE_LOG
  printf
    ("unzip_data: data_len = %d, unzip_len = %d, addr to be unzipped = %p\n",
     data_len, *unzip_len, data);
#endif

  int j = 0;
  /*
     for (int i = 0; i < data_len; i++)
     {
     printf("%02X ", data[i]);
     j++;
     if (j % 8 == 0)
     printf(" ");
     if (j % 16 == 0)
     printf("\n");
     }
   */

  if (!memcmp (data, "GET", strlen ("GET")))
    {
      *unzip_len = 0;
      *unzip_buf = NULL;
      return 1;
    }
  else if (!memcmp (data, "POST", strlen ("POST")))
    {
      unsigned char *data_copy_start = data;
      unsigned char *http_head_end =
	(unsigned char *) memmem (data, data_len, "\r\n\r\n",
				  strlen ("\r\n\r\n"));
      if (http_head_end != NULL)
	{
	  data_copy_start = http_head_end + 4;
	  int copy_len = data_len - (data_copy_start - data);
	  *unzip_buf = (unsigned char *) malloc (copy_len + 1);
	  *unzip_len = copy_len;
	  bzero (*unzip_buf, copy_len + 1);
	  memcpy (*unzip_buf, data_copy_start, copy_len);

	  return 0;
	}
      else
	return 1;

    }

  if ((pMem =
       (unsigned char *) memmem (data, data_len, "Content-Encoding: gzip",
				 strlen ("Content-Encoding: gzip"))) != NULL)
    {
      if ((content_start =
	   (unsigned char *) memmem (data, data_len, "\r\n\r\n", 4)) != NULL)
	{
	  zipped_length = data_len - (content_start - data + 4);
	  *unzip_buf = (unsigned char *) malloc (zipped_length * 16);
	  bzero (*unzip_buf, zipped_length * 16);
	  *unzip_len = zipped_length * 16;
#ifdef __HTTP_REASSEMBLE_LOG
	  printf
	    ("unzip_data: zipped data length = %d, call beap_uncompress()\n",
	     zipped_length);
#endif
	   //int ret = beap_uncompress_new (*unzip_buf, unzip_len, content_start + 4, &zipped_length);
	  int ret = beap_uncompress(*unzip_buf, unzip_len, content_start + 4, &zipped_length);
	  //int ret = ungzip(*unzip_buf, unzip_len, content_start + 4, zipped_length);
	  if (ret == 0)
	    {
#ifdef __HTTP_REASSEMBLE_LOG
	      printf
		("unzip_data: unzip success, unzipped data length = %d, return 0!\n",
		 *unzip_len);
#endif
	      return 0;
	    }
	  else
	    {
#ifdef __HTTP_REASSEMBLE_LOG
	      printf ("unzip_data: unzip failed, return 1!!!!!!!!1!\n");
#endif
	      *unzip_len = 0;
	      free (*unzip_buf);
	      *unzip_buf = NULL;
	      return 1;
	    }
	}
    }
  // if no chunk and no zip, copy the http body
  else
    {

      // added by zhangjl to remove HTTP HEAD
      unsigned char *http_head_end = NULL;
      unsigned char *data_copy_start = data;
      if (!memcmp (data, "HTTP/1.", strlen ("HTTP/1.")))
	{
	  http_head_end =
	    (unsigned char *) memmem (data, data_len, "\r\n\r\n",
				      strlen ("\r\n\r\n"));
	  if (http_head_end != NULL)
	    {
	      data_copy_start = http_head_end + 4;
	    }
	}
      // end added

      int copy_len = data_len - (data_copy_start - data);
      *unzip_buf = (unsigned char *) malloc (copy_len + 1);
      *unzip_len = copy_len;
      bzero (*unzip_buf, copy_len + 1);
      memcpy (*unzip_buf, data_copy_start, copy_len);
#ifdef __HTTP_REASSEMBLE_LOG
      printf ("unzip_data: no zipped data, get length of data = %d\n",
	      *unzip_len);
#endif

      return 0;
    }
  return -1;
}


int
cls_reassemble::atox (char *src)
{
  unsigned int dst = 0;
  int len = 0;
  unsigned char temp = 0, c = 0;
  int a = 0, j = 0, i = 0;

  if (strlen (src) > 8)
    {
      len = 8;
    }
  else
    {
      len = strlen (src);
    }
  for (i = len - 1; i >= 0; i--)
    {
      temp = 0;
      c = tolower (src[i]);
      //printf("EC_atox: character src[%d] = %c\n", i, c);
      if (c >= '0' && c <= '9')
	temp = c - '0';
      else if (c >= 'a' && c <= 'f')
	temp = c - 'a' + 0x0a;
      else
	return -1;

      //printf("EC_atox: temp = %d\n", temp);
      a = pow (16, (len - 1) - i);
      //printf("EC_atox: pow(16, (len - 1) - i) = %d\n", a);

      dst += temp * a;
      //printf("EC_atox: dst = %d\n", dst);
    }

  return dst;
}

char
cls_reassemble::beap_uncompress_new (unsigned char *uncompr,
					  unsigned int *uncompr_len,
					  unsigned char *compr,
					  unsigned int *compr_len)
{
  int err = 0;
  z_stream d_stream;
  static char dummy_head[2] = {
    0x8 + 0x7 * 0x10,
    (((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
  };

  d_stream.zalloc = NULL;
  d_stream.zfree = NULL;
  d_stream.opaque = NULL;
  //d_stream.next_in = (Bytef *) compr;
  d_stream.next_in = (Bytef *) compr;
  d_stream.avail_in = 0;
  //d_stream.next_out = (Bytef *) uncompr;
  d_stream.next_out = (Bytef *) uncompr;

  /* MAX_WBITS = 15 */
  if (inflateInit2 (&d_stream, MAX_WBITS + 16) != Z_OK)
    return 1;

  while ((d_stream.total_out < *uncompr_len)
	 && (d_stream.total_in < *compr_len))
    {
      d_stream.avail_in = d_stream.avail_out = 1;
      if ((err = inflate (&d_stream, Z_NO_FLUSH)) == Z_STREAM_END)
	break;

      if (err != Z_OK)
	{
	  if (err == Z_DATA_ERROR)
	    {
	      d_stream.next_in = (Bytef *) dummy_head;
	      d_stream.avail_in = sizeof (dummy_head);
	      if ((err = inflate (&d_stream, Z_NO_FLUSH)) != Z_OK)
		{
		  return 1;
		}
	    }
	  else
	    return 1;
	}
    }

  if (inflateEnd (&d_stream) != Z_OK)
    return 1;

  *uncompr_len = d_stream.total_out;

  return 0;

}


char cls_reassemble::beap_uncompress(unsigned char *uncompr, \
                       unsigned int  *uncompr_len, \
                       unsigned char *compr, \
                       unsigned int  *compr_len)
{
#define MAX_UNZIP_SIZE 320000
#define MIN_BUFSIZE    32768
#define MAX_BUFSIZE    1048576


    int err = Z_OK;
    int wbits = MAX_WBITS;
    int inits_num = 0;
	char *next = NULL;

    int     inlen;
    z_stream  stream;

    inlen = *compr_len;
	int bufsiz = inlen << 1;
	if ((bufsiz < MIN_BUFSIZE) || (bufsiz > MAX_BUFSIZE))
		bufsiz = MIN_BUFSIZE;
	bufsiz = *uncompr_len;
	next = (char*)compr;

    memset(&stream, 0, sizeof(z_stream));
    stream.next_in = (Bytef  *)compr;
    stream.avail_in = inlen;
    stream.next_out = (Bytef  *)uncompr;
    //stream.avail_out = MAX_UNZIP_SIZE;
    stream.avail_out = *uncompr_len;

    inits_num = 1;
    err = inflateInit2(&stream, wbits);
    if (err != Z_OK)
    {
        inflateEnd(&stream);
        return 1;
    }

    //while(inits_num <= 4)
    while(1)
    {
        stream.next_out = (Bytef  *)uncompr;
        stream.avail_out = *uncompr_len;

        err = inflate(&stream, Z_SYNC_FLUSH);

        if (err == Z_OK || err == Z_STREAM_END)
        {
            *uncompr_len = bufsiz - stream.avail_out;
            inflateEnd(&stream);
            return 0;
        }
        else if (err == Z_BUF_ERROR)
        {
            inflateEnd(&stream);
            return 1;
        }
        else if (err == Z_DATA_ERROR && \
                (*compr == 0x1f) && ((unsigned char)*(compr + 1) == 0x8b) &&\
                (inits_num == 1 /*|| inits_num == 3*/))
        {
    		char    *c = (char *)compr + 2;
	  		char     flags = 0;

            if (*c == Z_DEFLATED)
                c ++;
            else
			{
            	inflateEnd(&stream);
                return 1;
			}
            flags = *c;

            c += 7;
            if (flags & (1 << 2))
            {
                int size = (int)(*c | (*(c + 1) << 8));
                c += size;
            }

            if (flags & (1 << 3))
            {
                //while(*c != '\0')
                while(*c != '\0' && ((int)((unsigned char*)c - compr) < inlen))
                    c ++;
                c ++;
            }
            if (flags & (1 << 4))
            {
                //while(*c != '\0')
                while(*c != '\0' && (((unsigned char*)c - compr) < inlen))
                    c ++;
                c ++;
            }

            //inflateEnd(&stream);
            inflateReset(&stream);
			next = c;
            stream.next_in = (Bytef *)c;
			if ((unsigned char*)c - compr > inlen)
			{
				inflateEnd(&stream);
				return 1;
			}

            //inlen -= ((unsigned long) c - (unsigned long) compr);
            inlen -= (int)((unsigned char*)c - compr);
            //stream.avail_in = inlen;
            inflateInit2(&stream, wbits);
            inits_num ++;
            continue;
        }
        else if (err == Z_DATA_ERROR && inits_num <= 3)
        {
            wbits = -MAX_WBITS;
            //inflateEnd(&stream);
            inflateReset(&stream);
            //stream.next_in = (Bytef  *)compr;
            stream.next_in = (Bytef  *)next;
            stream.avail_in = *compr_len;
            inflateEnd(&stream);

			memset(uncompr, '\0', bufsiz);
            stream.next_out = (Bytef *)uncompr;
            stream.avail_out = bufsiz;
            err = inflateInit2(&stream, wbits);
            inits_num ++;
            if (err != Z_OK)
            {
                inflateEnd(&stream);
                return 1;
            }
            continue;
        }
		else
		{
            inflateEnd(&stream);
            return 1;
		}

    }
    inflateEnd(&stream);
    return 1;

}

// end of the file

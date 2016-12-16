/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <zlib.h>

#include "http_reassemble.h"

//#define __HTTP_REASSEMBLE_LOG



unsigned int http_sess_hash(void *key)
{
    int       i;
    unsigned long ret = 0;

    for (i = 0; i < sizeof(TCPsessionID); i++)
        ret += *((unsigned char *)((unsigned char *)key + i));

    unsigned int index = ret & MAX_INDEX_HTTP_HASH;
	//printf("http_sess_hash: index = %u\n", index);
	return index;
}

unsigned char http_sess_comp(void *key1, void *key2)
{
    TCPsessionID  *tcp_id1, *tcp_id2;

    if (!memcmp(key1, key2, sizeof(TCPsessionID)))
	{
		//printf("http_sess_comp: 111111111111\n");
        return 0;
	}

    tcp_id1 = (TCPsessionID *) key1;
    tcp_id2 = (TCPsessionID *) key2;
    if (tcp_id1 -> src_ip == tcp_id2 -> dst_ip &&\
        tcp_id1 -> dst_ip == tcp_id2 -> src_ip &&\
        tcp_id1 -> src_port == tcp_id2 -> dst_port &&\
        tcp_id1 -> dst_port == tcp_id2 -> src_port)
	{
        return 0;
	}

    return 1;
}

cls_http_reassemble::cls_http_reassemble()
{
    if (sem_init(&sem_http_hash, 0, 1) == -1)
    {
        printf("cls_http_reassemble: sem_init(sem_http_hash) error, exit!\n");
        exit(1);
    }

    if ((http_reassemble_tbl = create_hash(MAX_SIZE_HTTP_HASH, http_sess_hash, http_sess_comp)) == NULL)
    {
        printf("cls_http_reassemble: create_hash(http_reassemble_tbl) error, exit!\n");
        exit(1);
    }
    printf("cls_http_reassemble(): addr of http_reassemble_tbl = %p\n", http_reassemble_tbl);

    pthread_create(&hdl_http_hash_timer, NULL, http_cache_tbl_timer, (void*)this);
}

cls_http_reassemble::~cls_http_reassemble(){}

void* cls_http_reassemble::http_cache_tbl_timer(void *arg)
{
    cls_http_reassemble *pThis = reinterpret_cast<cls_http_reassemble*>(arg);
    pThis->do_timer();
}

void cls_http_reassemble::do_timer()
{
    while(1)
    {
        sleep(5);
        printf("%u, cls_http_reassemble do_timer() running, addr of http_reassemble_tbl = %p!!!\n", time(0), http_reassemble_tbl);

    }
    
}

char cls_http_reassemble::do_http_reassemble(TCPsessionID  sess_id,
                                             unsigned int  sdu_len, unsigned char *sdu_data,
                                             stru_http_req_head *http_header, enum TCPDirection dir,
                                             unsigned int  *http_data_len, unsigned char **http_data_buf)
{
#ifdef __HTTP_REASSEMBLE_LOG
	printf("do_http_reassemble: addr of http_reassemble = %p\n", http_reassemble_tbl);
	printf("do_http_reassemble: proto: %d, sip:%u, dip %u, sport:%d, dport:%d\n", 
           sess_id.proto, sess_id.src_ip, sess_id.dst_ip, sess_id.src_port, sess_id.dst_port);
#endif
    hash_bucket *pBucket = find_hash(http_reassemble_tbl, &sess_id);

    char           http_errno = 0;
    stru_http_info *http_obj = NULL;

    char to_get = 0;
    unsigned char *http_data = NULL;

    stru_http_req_head temp_head;
    bzero(&temp_head, sizeof(temp_head));


    if (pBucket == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
		printf("do_http_reassemble: find_hash == NULL, method = %d\n", http_header->method);
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
            printf("process_http: the first SDU is not a http req, error\n");
#endif
            http_errno = 1;
            goto LABEL_SEM_POST;
        }

        // 如果HTTP REQ不完整,解析出错,则错误返回
        if (analyse_http_req(sdu_data, sdu_len, &temp_head))
        {
#ifdef __HTTP_REASSEMBLE_LOG
            printf("process_http: analyse_http_req error\n");
#endif
            http_errno = 1;
            goto LABEL_SEM_POST;
        }

        http_obj = (stru_http_info*)calloc(1, sizeof(stru_http_info));
        http_obj->sessid = sess_id;
        http_obj->method = temp_head.method;
        http_obj->status = temp_head.tailer_bingo ? (S_REQ_HEAD_END) : (S_REQ_HEAD_START);
        http_obj->req_head_len = temp_head.head_len;
        http_obj->req_body_len = temp_head.content_len;
        http_obj->req_got_len = sdu_len;
        
        if (temp_head.url[0] != '\0')
            strncpy(http_obj->url, temp_head.url, sizeof(http_obj->url));
        if (temp_head.host[0] != '\0')
            strncpy(http_obj->host, temp_head.host, sizeof(http_obj->host));
        if (temp_head.content_type[0] != '\0')
            strncpy(http_obj->content_type, temp_head.content_type, sizeof(http_obj->content_type));

#ifdef __HTTP_REASSEMBLE_LOG
	printf("do_http_reassemble: find_hash==NULL, get req infO, \
                status = %d, req_head_len = %d, req_body_len = %d, req_got_len = %d\n", \
                http_obj->status, http_obj->req_head_len, http_obj->req_body_len, http_obj->req_got_len);
#endif

        insert_list(&(http_obj->sdu_list_up), sdu_data, sdu_len);
        
        pBucket = (hash_bucket*)calloc(1, sizeof(hash_bucket));
        pBucket->key = &(http_obj->sessid);
        pBucket->content = (void*)http_obj;
        insert_hash(http_reassemble_tbl, pBucket);
    }
    // 对于既有连接的处理,这里比新连接的处理要复杂的多,需要考虑很多种情况
    // 对于HTTP RESP消息,一定会在这个分支中处理
    else
    {
#ifdef __HTTP_REASSEMBLE_LOG
		printf("do_http_reassemble: find_hash != NULL, http_header->method = %d........\n", http_header->method);
#endif
        // 这里的要处理的情况包括:
        // (1) 一个POST请求报文的BODY及其后续部分,此时http_status==REQ_HEAD_END
        // (2) 一个GET请求的全部内容或一个POST请求的完整头部,此时http_status==RESP_END
        // (3) 一个response回应的完整头部此时http_status==REQ_END
        // (4) 一个response回应的BODY及其后续部分,此时http_status==RESP_HEAD_END
        // (5) 一个response回应的完整内容,此时http_status==REQ_END
        http_obj = (stru_http_info*)(pBucket->content);

#ifdef __HTTP_REASSEMBLE_LOG
		printf("do_http_reassemble: find_hash != NULL, http_info, status = %d\n", http_obj->status);
#endif

        // 如果是一个已经存在的连接,且当前收到了一个新的HTTP REQ, 说明此前的HTTP数据发生丢失,
        // 此时,将此前的所有缓存数据清空(如果保留该怎么处理????),重新缓存当前REQ对应的数据

        // 对于从CLIENT发往SERVER端的数据,若不是新的HTTP_REQ,那么只有在当前状态为S_REQ_HEAD_START/
        // S_REQ_HEAD_END/S_RSP_END的情况下才应该处理
        if (dir == FROM_CLIENT)
        {
#ifdef __HTTP_REASSEMBLE_LOG
	    	printf("do_http_reassemble: find_hash!=NULL, dir== FROM_CLIENT.....\n");
#endif
            if (http_header->method == 1 || http_header->method == 2)
            {
#ifdef __HTTP_REASSEMBLE_LOG
				printf("dir==FROM_CLIENT, a new http_req, clear all the old data in link_list\n");
#endif
                free_list(&(http_obj->sdu_list_up)); // 清空当前的所有已缓存数据
                free_list(&(http_obj->sdu_list_down));
            
                if (analyse_http_req(sdu_data, sdu_len, &temp_head))
                {
#ifdef __HTTP_REASSEMBLE_LOG
                    printf("process_http: analyse_http_req error\n");
#endif
                    http_errno = 1;
                    goto LABEL_SEM_POST;
                }

                bzero(http_obj, sizeof(stru_http_info));
				http_obj->sessid = sess_id;
                http_obj->method = temp_head.method;
                http_obj->status = temp_head.tailer_bingo ? (S_REQ_HEAD_END) : (S_REQ_HEAD_START);
                http_obj->req_head_len = temp_head.head_len;
                http_obj->req_body_len = temp_head.content_len;
                //http_obj->req_got_len = sdu_len;
        
                if (temp_head.url[0] != '\0')
                    strncpy(http_obj->url, temp_head.url, sizeof(http_obj->url));
                if (temp_head.host[0] != '\0')
                    strncpy(http_obj->host, temp_head.host, sizeof(http_obj->host));
                if (temp_head.content_type[0] != '\0')
                    strncpy(http_obj->content_type, temp_head.content_type, sizeof(http_obj->content_type));

#ifdef __HTTP_REASSEMBLE_LOG
				printf("dir==FROM_CLIENT, analyse_http_req, method = %d, status = %d, \
                       req_head_len = %d, req_body_len = %d, req_got_len = %d\n", http_obj->method, \
                       http_obj->status,http_obj->req_head_len,http_obj->req_body_len,http_obj->req_got_len);
#endif

                //insert_list(&(http_obj->sdu_list_up), sdu_data, sdu_len);
            }
            else
            {
                if (!(http_obj->status == S_RSP_END ||
                      http_obj->status == S_REQ_HEAD_END || http_obj->status == S_REQ_HEAD_START))
                {
#ifdef __HTTP_REASSEMBLE_LOG
                    printf("dir==DIR_CLIENT, recv a up_data in the wrong status, goto LABEL_SEM_POST\n");
#endif
                    http_errno = 1;
                    goto LABEL_SEM_POST;
                }
            }

            insert_list(&(http_obj->sdu_list_up), sdu_data, sdu_len);
            http_obj->req_got_len += sdu_len;
#ifdef __HTTP_REASSEMBLE_LOG
            printf("dir==FROM_CLIENT, save the sdu_data in sdu_list_up, req_got_len = %d\n", http_obj->req_got_len);
#endif
        }
        // 对于从SERVER端发往CLIENT的数据,只有在当前状态为S_REQ_END/S_RSP_HEAD_END的情况下才应该处理
        else if (dir == FROM_SERVER)
        {
            if (!(http_obj->status == S_REQ_END || http_obj->status == S_RSP_HEAD_END))
            {
#ifdef __HTTP_REASSEMBLE_LOG
                printf("dir==FROM_SERVER, recv a down_data in the wrong status, goto LABEL_SEM_POST\n");
#endif
                http_errno = 1;
                goto LABEL_SEM_POST;
            }

            // 这里,要判断当前SDU是否是HTTP RSP的第一个数据单元,若是的话,要从中解析出相应的信息.比如:
            // content-type/transfer-encoding/content-encoding等字段内容
            bzero(&temp_head, sizeof(temp_head));
            if (analyse_http_resp(sdu_data, sdu_len, &temp_head))
            {
#ifdef __HTTP_REASSEMBLE_LOG
                printf("process_http: analyse_http_resp error\n");
#endif
                http_errno = 1;
                goto LABEL_SEM_POST;
            }
            
            if (temp_head.method == method_resp)
            {
#ifdef __HTTP_REASSEMBLE_LOG
				printf("dir==FROM_SERVER, a new http resp, clear the old data in link_list\n");
#endif
                free_list(&http_obj->sdu_list_down);

                http_obj->status = S_RSP_HEAD_END;
                http_obj->rsp_chunk_flag = temp_head.chunk_flag;
                http_obj->rsp_gzip_flag = temp_head.gzip_flag;
                http_obj->rsp_head_len = temp_head.head_len;
                http_obj->rsp_body_len = temp_head.content_len;
				http_obj->type_text_flag = temp_head.type_text_flag;
                strncpy(http_obj->content_type, temp_head.content_type, sizeof(temp_head.content_type));

#ifdef __HTTP_REASSEMBLE_LOG
		printf("a new http resp, http_info, status = %d, url = %s, host = %s, rsp_chunk_flag = %d, \
                        rsp_gzip_flag = %d, rsp_head_len = %d, rsp_body_len = %d\n", \
                        http_obj->status, http_obj->url, http_obj->host, http_obj->rsp_chunk_flag, \
                        http_obj->rsp_gzip_flag, http_obj->rsp_head_len, http_obj->rsp_body_len);
#endif
            }

            insert_list(&(http_obj->sdu_list_down), sdu_data, sdu_len);
            http_obj->rsp_got_len += sdu_len;
                
#ifdef __HTTP_REASSEMBLE_LOG
            printf("dir==FROM_SERVER, save the sdu_data in sdu_list_down, rsp_got_len = %d\n", http_obj->rsp_got_len);
#endif
        }

        switch(http_obj->status)
        {
        }
    }
   	find_hash(http_reassemble_tbl, &sess_id);

#ifdef __HTTP_REASSEMBLE_LOG
    printf("http_obj->status = %d\n", http_obj->status);
#endif

    // 接下来根据hash表中的http_obj的status来决定当前需要重组返回的是完整的http req还是http resp.
    // 若是http_req,则根据req_len和req_got_len来判断REQ是否完整
    // 若是http_resp,则根据resp_len和resp_got_len来判断RESP是否完整.对于chunk的RESP,则需要
    // 根据chunk_tailer来判断RESP是否完整

    to_get = 0;
    switch(http_obj->status)
    {
        case S_REQ_HEAD_START:
            to_get = 0;
#ifdef __HTTP_REASSEMBLE_LOG
            printf("process_http: case S_REQ_HEAD_START, break.........\n");
#endif
            break;
        case S_REQ_HEAD_END:
#ifdef __HTTP_REASSEMBLE_LOG
            printf("process_http: case S_REQ_HEAD_END, go on doing.........\n");
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
	    printf("req_got_len = %d, req_head_len = %d, req_body_len = %d\n",
                   http_obj->req_got_len, http_obj->req_head_len, http_obj->req_body_len);
#endif
            if (http_obj->req_got_len >= (http_obj->req_head_len + http_obj->req_body_len))
            {
                to_get = 1;
                http_data = (unsigned char*)calloc(http_obj->req_got_len, sizeof(unsigned char));
                *http_data_len = http_obj->req_got_len;
                get_list_data(http_obj->sdu_list_up, http_data);
                free_list(&(http_obj->sdu_list_up));
                free_list(&(http_obj->sdu_list_down));
                http_obj->status = S_REQ_END;
				//printf("set http_obj->status = %d\n", S_REQ_END);

            }
            else
				to_get = 0;
            break;
        case S_REQ_END:
#ifdef __HTTP_REASSEMBLE_LOG
            printf("process_http: case S_REQ_END, break.........\n");
#endif
            break;
        case S_RSP_HEAD_START:
#ifdef __HTTP_REASSEMBLE_LOG
            printf("process_http: case S_RSP_HEAD_START, break.........\n");
#endif
            break;
        case S_RSP_HEAD_END:
            // 对于HTTP RESP的结束判断,不能像REQ一样只根据got_len进行.要区分是否有chunk分块.对于没有chunk分块的
            // RESP,根据got_len判断即可.但对于做了chunk分块的response,需要在当前SDU中查找chunk_tailer来判定
            // 当前http response是否已经结束.
#ifdef __HTTP_REASSEMBLE_LOG
	    	printf("process_http: case S_RSP_HEAD_END, go on dong......\n");
            printf("rsp_got_len = %d, rsp_head_len = %d, rsp_body_len = %d\n", \
                    http_obj->rsp_got_len, http_obj->rsp_head_len, http_obj->rsp_body_len);
#endif
            if ((http_obj->rsp_chunk_flag == 0) && (http_obj->rsp_got_len >= (http_obj->rsp_head_len + http_obj->rsp_body_len)))
	    	{
#ifdef __HTTP_REASSEMBLE_LOG
                printf("http resp not chunk, set to_get == 1\n");
#endif
                to_get = 1;
            }
            else if (http_obj->rsp_chunk_flag)
	    	{
                if (!memcmp(sdu_data + sdu_len - 5, "0\r\n\r\n", 5))
                {
#ifdef __HTTP_REASSEMBLE_LOG
                   printf("http resp with chunk, find chunk tailer, set to_get == 1\n");
#endif
                   to_get = 1;
                }
                else
                   to_get = 0;
            }
            else
            {
                to_get = 0;
#ifdef __HTTP_REASSEMBLE_LOG
                printf("http resp, set to_get==0\n");
#endif
            }
            if (to_get == 1)
            {
                http_data = (unsigned char*)calloc(http_obj->rsp_got_len, sizeof(unsigned char));
                *http_data_len = http_obj->rsp_got_len;
                get_list_data(http_obj->sdu_list_down, http_data);
                free_list(&(http_obj->sdu_list_up));
                free_list(&(http_obj->sdu_list_down));
	        	http_obj->status = S_RSP_END;
#ifdef __HTTP_REASSEMBLE_LOG
                printf("to_get == 1, set http_obj->status = %d\n", S_RSP_END);
#endif

                http_header->gzip_flag = http_obj->rsp_chunk_flag;
                http_header->chunk_flag = http_obj->rsp_chunk_flag;
				http_header->type_text_flag = http_obj->type_text_flag;
            }
            break;
        case S_RSP_END:
#ifdef __HTTP_REASSEMBLE_LOG
            printf("process_http: case S_RSP_END, break.........\n");
#endif
            break;
        default:
            break;
    }

    
LABEL_SEM_POST:
    sem_post(&sem_http_hash);

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

int cls_http_reassemble::insert_list(stru_tcpsdu_node **head,unsigned char *data,int data_len)
{
    if(data_len <= 0)
        return 0;

    stru_tcpsdu_node *temp = NULL;
    stru_tcpsdu_node *new_Bucket = (stru_tcpsdu_node *)malloc(sizeof(stru_tcpsdu_node));
    bzero(new_Bucket, sizeof(stru_tcpsdu_node));
    new_Bucket->data = (unsigned char *)malloc(data_len + 1);
    bzero(new_Bucket->data, data_len+1);
    memcpy(new_Bucket->data, data,data_len);
    new_Bucket->data_len = data_len;
    new_Bucket->next = NULL;

    //printf("insert_list: addr of new node: %p\n", new_Bucket);

    if(*head == NULL)
    {
        *head = new_Bucket;
    }
    else
    {
        temp = *head;
        while(temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = new_Bucket;
    }
}

int cls_http_reassemble::get_list_data(stru_tcpsdu_node *head,unsigned char *data)
{
    int pos = 0;
    while(head != NULL)
    {
        memcpy(data + pos, head->data, head->data_len);
        pos += head->data_len;
        head = head->next;
    }
    return 0;
}

int cls_http_reassemble::free_list(stru_tcpsdu_node **head)
{
    if(head == NULL || *head == NULL)
        return 0;

    //printf("free_list: addr of list: %p, addr of first node: %p\n", head, *head);

    stru_tcpsdu_node *cur = (*head);
    stru_tcpsdu_node *next = (*head)->next;
    while(cur != NULL)
    {
        next = cur->next;
        if(cur->data != NULL)
        {
            free(cur->data);
            cur->data = NULL;
        }
        free(cur);
        cur = next;
    }

    *head = NULL;
}

char cls_http_reassemble::analyse_http_req(unsigned char *data, unsigned int datalen, stru_http_req_head *header)
{
    // 缓冲区为空或者长度过小,错误返回
    if (data == NULL || datalen < 20)
        return 1;

    unsigned char *p_url_start = NULL, *p_url_end = NULL;
    if (memcmp(data, "GET ", 4) == 0)
    {
        header->method = method_get;
        p_url_start = data + 4;
    }
    else if (memcmp(data, "POST ", 5) == 0)
    {
        header->method = method_post;
        p_url_start = data + 5;
    }
    else
        return 1;
    
    // the request packet doesn't contain \n, return
    unsigned char *p_head_tailer = (unsigned char*)memmem(data, datalen, "\n", 1);
    if (p_head_tailer == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
        printf("can't 2222222222 tailer!!!!\n");
#endif
        return 1;
    }
    int find_len = p_head_tailer - data;
#ifdef __HTTP_REASSEMBLE_LOG
    printf("datalen = %d, find_len = %d\n", datalen, find_len);
#endif

    // get the http version
    unsigned char *p_http_ver = (unsigned char*)memmem(data, find_len, "HTTP", 4);
    if (p_http_ver == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
        printf("can't 3333333333 HTTP!!!!\n");
#endif
        return 1;
    }

    p_url_end = (*(p_http_ver - 1) = ' ') ? (p_http_ver - 1) : (p_http_ver);

    unsigned char url[256];
    bzero(url, sizeof(url));
	int copy_len = p_url_end - p_url_start;
	if (copy_len >= sizeof(url))
		copy_len = sizeof(url) - 1;

    //memcpy(url, p_url_start, p_url_end - p_url_start);
    memcpy(url, p_url_start, copy_len);
#ifdef __HTTP_REASSEMBLE_LOG
    printf("get_http_req_head: url = <%s>\n", url);
#endif
    strncpy(header->url, (const char*)url, sizeof(url) - 1);

    // the request packet doesn't contain Host header, return
    unsigned char *p_host = (unsigned char*)memmem(data, datalen, "Host: ", 6);
    if (p_host == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
        printf("44444444444 HOST error!!!!\n");
#endif
        return 1;
    }

    p_head_tailer = (unsigned char*)memmem(p_host, datalen - (p_host - data), "\n", 1);
    if (p_head_tailer == NULL)
    {
        return 1;
    }

    unsigned char host[256];
    bzero(host, sizeof(host));
    if (*(p_head_tailer - 1) == '\r')
        p_head_tailer--;
    
    memcpy(host, p_host + 6, p_head_tailer - p_host - 6);
#ifdef __HTTP_REASSEMBLE_LOG
    printf("get_http_req_head: host = <%s>\n", host);
#endif
    strcpy(header->host, (const char*)host);

    if (header->method == method_post)
    {
        unsigned char *p_len = (unsigned char*)memmem(data, datalen, "Content-Length: ", 16);
        if (p_len != NULL)
        {
            p_head_tailer = (unsigned char*)memmem(p_len, datalen - (p_len - data), "\n", 1);
            if (p_head_tailer != NULL)
            {
                if (*(p_head_tailer - 1) == '\r')
                    p_head_tailer--;

                unsigned char len[16];
                bzero(len, sizeof(len));
                memcpy(len, p_len + 16, p_head_tailer - p_len - 16);
                header->content_len = atoi((const char*)len);
#ifdef __HTTP_REASSEMBLE_LOG
                printf("http post req, get content_len = %d\n", header->content_len);
#endif
            }
        }

        unsigned char *p_type = (unsigned char*)memmem(data, datalen, "Content-Type: ", 14);
        if (p_type != NULL)
        {
            p_head_tailer = (unsigned char*)memmem(p_type, datalen - (p_type - data), "\n", 1);
            if (p_head_tailer != NULL)
            {
                if (*(p_head_tailer - 1) == '\r')
                    p_head_tailer--;
                
                memcpy(header->content_type, p_type + 14, p_head_tailer - p_type - 14);
#ifdef __HTTP_REASSEMBLE_LOG
                printf("http post req, get content-type = %s\n", header->content_type);
#endif

                if ((strstr((const char*)(header->content_type), "text/html") != NULL) ||
                     (strstr((const char*)(header->content_type), "text/javascript") != NULL) ||
                     (strstr((const char*)(header->content_type), "application/x-gzip") != NULL) ||
                     (strstr((const char*)(header->content_type), "application/x-msgpack") != NULL))
                    header->type_text_flag = 1;
                else
                    header->type_text_flag = 0;
            }
        }
    }

    // the request need tcp_reassemble, return
    if ((p_head_tailer = (unsigned char*)memmem(data, datalen, "\r\n\r\n", 4)) != NULL)
    {
        header->head_len = p_head_tailer - data + 4;
#ifdef __HTTP_REASSEMBLE_LOG
        printf("http req, get head_len = %d\n", header->head_len);
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

char cls_http_reassemble::analyse_http_resp(unsigned char *data, unsigned int datalen, stru_http_req_head *header)
{
    // 缓冲区为空或者长度过小,错误返回
    if (data == NULL || datalen < 20)
        return 1;

    if (memcmp(data, "HTTP/", 5))
    {
        return 0;
    }

    unsigned char *p_head_tailer = (unsigned char*)memmem(data, datalen, "\r\n\r\n", 4);
    if (p_head_tailer == NULL)
    {
        return 1;
    }
    
    header->method = method_resp;
    header->head_len = p_head_tailer - data + 4;

    p_head_tailer = (unsigned char*)memmem(data, datalen, "\n", 1);
    if (p_head_tailer == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
        printf("can't 2222222222 tailer!!!!\n");
#endif
        return 1;
    }

    unsigned char *p_type = (unsigned char*)memmem(data, datalen, "Content-Type: ", 14);
    if (p_type != NULL)
    {
        p_head_tailer = (unsigned char*)memmem(p_type, datalen - (p_type - data), "\n", 1);
        if (p_head_tailer != NULL)
        {
            if (*(p_head_tailer - 1) == '\r')
                p_head_tailer--;
                
            memcpy(header->content_type, p_type + 14, p_head_tailer - p_type - 14);
#ifdef __HTTP_REASSEMBLE_LOG
            printf("http response, get content-type = %s\n", header->content_type);
#endif
            if ((strstr((const char*)(header->content_type), "text/html") != NULL) ||
                     (strstr((const char*)(header->content_type), "text/javascript") != NULL) ||
                     (strstr((const char*)(header->content_type), "application/x-gzip") != NULL) ||
                     (strstr((const char*)(header->content_type), "application/x-msgpack") != NULL))
                header->type_text_flag = 1;
            else
                header->type_text_flag = 0;
        }
    }

    unsigned char *p_len = (unsigned char*)memmem(data, datalen, "Content-Length: ", 16);
    if (p_len != NULL)
    {
        p_head_tailer = (unsigned char*)memmem(p_len, datalen - (p_len - data), "\n", 1);
        if (p_head_tailer != NULL)
        {
            if (*(p_head_tailer - 1) == '\r')
                p_head_tailer--;

            unsigned char len[16];
            bzero(len, sizeof(len));
            memcpy(len, p_len + 16, p_head_tailer - p_len - 16);
            header->content_len = atoi((const char*)len);
#ifdef __HTTP_REASSEMBLE_LOG
            printf("http response, get content_len = %d\n", header->content_len);
#endif
        }
    }

    unsigned char *p_trancode = (unsigned char*)memmem(data, datalen, "Transfer-Encoding: ", 19);
    if (p_trancode != NULL)
    {
        p_head_tailer = (unsigned char*)memmem(p_trancode, datalen - (unsigned int)(p_trancode - data), "\n", 1);
        if (p_head_tailer != NULL)
        {
            if (*(p_head_tailer - 1) == '\r')
                p_head_tailer--;

            header->chunk_flag = 1;
#ifdef __HTTP_REASSEMBLE_LOG
            printf("http response, get chunk_flag =1 \n");
#endif
        }
    }

    unsigned char *p_contcode = (unsigned char*)memmem(data, datalen, "Content-Encoding: ", 18);
    if (p_contcode != NULL)
    {
        p_head_tailer = (unsigned char*)memmem(p_contcode, datalen - (p_contcode - data), "\n", 1);
        if (p_head_tailer != NULL)
        {
            if (*(p_head_tailer - 1) == '\r')
                p_head_tailer--;

            unsigned char cont_coding[32];
            bzero(cont_coding, sizeof(cont_coding));
            memcpy(cont_coding, p_contcode + 18, p_head_tailer - p_contcode - 18);
#ifdef __HTTP_REASSEMBLE_LOG
            printf("http response, get content-encoding: (%s)\n", cont_coding);
#endif
            header->gzip_flag = 1;
        }
    }
    
    return 0;
}

int cls_http_reassemble::dechunk_data(unsigned char *data, unsigned int *data_len)
{
    unsigned char *pos_head_end = NULL; 
    unsigned char *pos_body_start = NULL; 
    unsigned char *pos_chunk_tailer = NULL; 
    unsigned char *pos_chunk_size_end = NULL; 
    unsigned char *pos_chunk_data_begin = NULL; 
    unsigned char chunk_tailer[] = "0\r\n";
    unsigned char http_head_end[]= "\r\n\r\n";
    unsigned char chunk_size_end[] = "\r\n"; 
    unsigned char chunk_data_end[] = "\r\n"; 

    int i = 0;
    int j = 0;
    int  http_head_end_len = sizeof(http_head_end) - 1;
    int  chunk_tailer_len = sizeof(chunk_tailer) - 1;
    int  chunk_size_end_len = sizeof(chunk_size_end) - 1;
    int  chunk_data_end_len = sizeof(chunk_size_end) - 1;
    int  chunk_size_len = 0;
    int  chunk_data_len = 0;
    int  header_len = 0, body_len = 0;

    int cache_len = *data_len;
    unsigned char *cache_data = (unsigned char*)malloc(cache_len);
    bzero(cache_data, cache_len);
    memcpy(cache_data, data, cache_len);
#ifdef __HTTP_REASSEMBLE_LOG
    printf("dechunk_data: http_head_end_len = %d, chunk_tailer_len = %d, chunk_size_end_len = %d\n", \
           http_head_end_len, chunk_tailer_len, chunk_size_end_len);
    printf("dechunk_data: cache_len = %d, cache_data's content is as follows:\n", cache_len);
#endif

#if 0
    for (i = 0; i < cache_len; i++)
    { 
        printf("%02X ", cache_data[i]);
        j++;    
        if (j % 8 == 0) 
            printf("  ");
        if (j % 16 == 0)
            printf("\n");
    }
    printf("\n");
#endif

    if ((pos_head_end = (unsigned char*)memmem(cache_data, cache_len, http_head_end, http_head_end_len)) == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
        printf("dechunk_data: there is no http_header_end, error and return -1!!!\n");
#endif
        free(cache_data);
        cache_data = NULL;
        return -1;
    }

    pos_body_start = pos_head_end + http_head_end_len;
    header_len = pos_body_start - cache_data;
    body_len = cache_len - header_len;

#ifdef __HTTP_REASSEMBLE_LOG
    printf("dechunk_data: check http header pass, header_len = %d, chunked body_len = %d, go on dechunk\n", \
           header_len, body_len);
#endif

    if ((pos_chunk_tailer = (unsigned char*)memmem(pos_body_start, body_len, chunk_tailer, chunk_tailer_len)) == NULL)
    {
#ifdef __HTTP_REASSEMBLE_LOG
        printf("dechunk_data: there is no chunk_tailer, error and return -1!!!\n");
#endif
        free(cache_data);
        cache_data = NULL;
        return -1;
    }

    // clear data buf to save dechunked data
    bzero(data, *data_len);
    *data_len = 0;

    // get the chunked http body data and dechunked it, first copy the http_header to dechunked data buf
    unsigned char *pos_copy_begin = data;
    int copy_len = header_len;
    memcpy(pos_copy_begin, cache_data, copy_len);
    pos_copy_begin += copy_len;
    *data_len += copy_len;

#ifdef __HTTP_REASSEMBLE_LOG
    printf("dechunk_data: check chunk_tailer pass, first copy http_header, header_len = %d, have copyed_len = %d, then go on processing!!\n", copy_len, *data_len);
#endif
    
    // second: get the chunked data's length, only copy the chunked data to dechunked data buf, do util the tailer chunked data
    unsigned char str_chunk_size[16];
    int    str_chunk_size_len = 0;
    unsigned char *chunked_data_begin = pos_body_start;
    int chunked_data_len = body_len;
    pos_chunk_size_end = (unsigned char*)memmem(chunked_data_begin, chunked_data_len, chunk_size_end, chunk_size_end_len);

    int dechunked_data_len = 0;

#ifdef __HTTP_REASSEMBLE_LOG
    printf("dechunk_data: dechunk the http_body, length of data to be dechunked = %d\n", chunked_data_len);
#endif


    // get every chunked data's length and dechunk it
    while(pos_chunk_size_end != NULL)
    {
        bzero(str_chunk_size, sizeof(str_chunk_size));
        str_chunk_size_len = pos_chunk_size_end - chunked_data_begin;
        memcpy(str_chunk_size, chunked_data_begin, str_chunk_size_len);
        copy_len = atox((char*)str_chunk_size);

        if (copy_len == -1)
        {
            free(cache_data);
            cache_data = NULL;
            return -1;
            break;
        }

#ifdef __HTTP_REASSEMBLE_LOG
        printf("dechunk_data, get sting of chunk size: %s, chunk_len = copy_len = %d\n", str_chunk_size, copy_len);
#endif

        if (copy_len == 0)
            break;
        bzero(str_chunk_size, sizeof(str_chunk_size));
        str_chunk_size_len = pos_chunk_size_end - chunked_data_begin;
        memcpy(str_chunk_size, chunked_data_begin, str_chunk_size_len);
        copy_len = atox((char*)str_chunk_size);

        if (copy_len == -1)
        {
            free(cache_data);
            cache_data = NULL;
            return -1;
            break;
        }

#ifdef __HTTP_REASSEMBLE_LOG
        printf("dechunk_data, get sting of chunk size: %s, chunk_len = copy_len = %d\n", str_chunk_size, copy_len);
#endif

        if (copy_len == 0)
            break;

        // copy to data and set the new copy_position
        dechunked_data_len += copy_len;
        *data_len += copy_len;

        if (*data_len >= cache_len)
        {
            free(cache_data);
            cache_data = NULL;
            return -1;
        }
        memcpy(pos_copy_begin, pos_chunk_size_end + chunk_size_end_len, copy_len);
        pos_copy_begin += copy_len;

        //printf("dechunked_data: copy_len > 0, copy to destination\n");

        // locate the begin position of the next chunked data
        chunked_data_begin = pos_chunk_size_end + chunk_size_end_len + copy_len + chunk_size_end_len;
        chunked_data_len = chunked_data_len - (str_chunk_size_len + chunk_size_end_len + copy_len + chunk_data_end_len);
        pos_chunk_size_end = (unsigned char*)memmem(chunked_data_begin, chunked_data_len, chunk_size_end, chunk_size_end_len);

#ifdef __HTTP_REASSEMBLE_LOG
        printf("dechunk_data, copy chunked data, copy_len = %d, dechunked_data_len = %d, to be dechunked_len = %d\n", \
               copy_len, dechunked_data_len, chunked_data_len);
#endif
    }

#if 0
    printf("dechunk_data: dechunked_data_len = %d, content is as follows:\n", dechunked_data_len);
    for (i = 0; i < dechunked_data_len; i++)
    {
        printf("%02X ", *(data + header_len + i));
        j++;
        if (j % 8 == 0)
            printf("  ");
        if (j % 16 == 0)
            printf("\n");
    }
    printf("\n");

#endif

    free(cache_data);
    cache_data = NULL;

    return 0;
}

int cls_http_reassemble::unzip_data(unsigned char *data, unsigned int data_len, unsigned char **unzip_buf, unsigned int *unzip_len)
{
    unsigned char *pMem = NULL;
    unsigned char *p =  NULL,*q = NULL,*content_start=NULL;
    char pLength[128];
    unsigned int zipped_length = 0;

#ifdef __HTTP_REASSEMBLE_LOG
    printf("unzip_data: data_len = %d, unzip_len = %d, addr to be unzipped = %p\n", data_len, *unzip_len, data);
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

    if (!memcmp(data, "GET", strlen("GET")))
	{
		*unzip_len = 0;
		*unzip_buf = NULL;
		return 1;
	}
	else if (!memcmp(data, "POST", strlen("POST")))
	{
        unsigned char *data_copy_start = data;
        unsigned char *http_head_end = (unsigned char*)memmem(data, data_len, "\r\n\r\n", strlen("\r\n\r\n"));
        if (http_head_end != NULL)
        {
			data_copy_start = http_head_end + 4;
        	int copy_len = data_len - (data_copy_start - data);
        	*unzip_buf = (unsigned char *)malloc(copy_len+1);
        	*unzip_len = copy_len;
        	bzero(*unzip_buf, copy_len + 1);
        	memcpy(*unzip_buf, data_copy_start, copy_len);

			return 0;
        }
		else
			return 1;
		
	}

    if((pMem = (unsigned char *)memmem(data,data_len,"Content-Encoding: gzip",strlen("Content-Encoding: gzip"))) != NULL)
    {
        if ((content_start = (unsigned char*)memmem(data, data_len, "\r\n\r\n", 4)) != NULL)
        {
            zipped_length = data_len - (content_start - data + 4);
            *unzip_buf = (unsigned char *)malloc(zipped_length*16);
            bzero(*unzip_buf, zipped_length*16);
            *unzip_len = zipped_length*16;
#ifdef __HTTP_REASSEMBLE_LOG
            printf("unzip_data: zipped data length = %d, call beap_uncompress()\n", zipped_length);
#endif
            int ret = beap_uncompress_new(*unzip_buf, unzip_len, content_start + 4, &zipped_length);
            if(ret == 0)
            {
#ifdef __HTTP_REASSEMBLE_LOG
                printf("unzip_data: unzip success, unzipped data length = %d, return 0!\n", *unzip_len);
#endif
                return 0;
            }
            else
            {
#ifdef __HTTP_REASSEMBLE_LOG
                printf("unzip_data: unzip failed, return 1!!!!!!!!1!\n");
#endif
				*unzip_len = 0;
				free(*unzip_buf);
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
        if (!memcmp(data, "HTTP/1.", strlen("HTTP/1.")))
        {
            http_head_end = (unsigned char*)memmem(data, data_len, "\r\n\r\n", strlen("\r\n\r\n"));
            if (http_head_end != NULL)
            {
                data_copy_start = http_head_end + 4;
            }
        }
        // end added

        int copy_len = data_len - (data_copy_start - data);
        *unzip_buf = (unsigned char *)malloc(copy_len+1);
        *unzip_len = copy_len;
        bzero(*unzip_buf, copy_len + 1);
        memcpy(*unzip_buf, data_copy_start, copy_len);
#ifdef __HTTP_REASSEMBLE_LOG
        printf("unzip_data: no zipped data, get length of data = %d\n", *unzip_len);
#endif

        return 0;
    }
    return -1;
}


int cls_http_reassemble::atox(char *src)
{
        unsigned int dst = 0;
        int len = 0;
        unsigned char temp = 0,c = 0;
        int a = 0,j = 0,i = 0;

        if(strlen(src) > 8)
        {
                len = 8;
        }
        else
        {
                len = strlen(src);
        }
        for (i = len - 1; i >= 0; i--)
        {
            temp = 0;
            c = tolower(src[i]);
            //printf("EC_atox: character src[%d] = %c\n", i, c);
            if (c >= '0' && c <= '9')
                temp = c - '0';
            else if (c >= 'a' && c <= 'f')
                temp = c - 'a' + 0x0a;
            else
                return -1;

            //printf("EC_atox: temp = %d\n", temp);
            a = pow(16, (len - 1) - i);
            //printf("EC_atox: pow(16, (len - 1) - i) = %d\n", a);

            dst += temp*a;
            //printf("EC_atox: dst = %d\n", dst);
        }

        return dst;
}

char cls_http_reassemble::beap_uncompress_new(unsigned char *uncompr, \
                       unsigned int *uncompr_len, \
                       unsigned char *compr, \
                       unsigned int *compr_len)
{
    int err = 0;
    z_stream d_stream;
    static char dummy_head[2] = {
        0x8 + 0x7*0x10,
        (((0x8 + 0x7*0x10)*0x100 + 30) / 31 * 31) & 0xFF,
    };

    d_stream.zalloc = NULL;
    d_stream.zfree = NULL;
    d_stream.opaque = NULL;
    d_stream.next_in = (Bytef*)compr;
    d_stream.avail_in = 0;
    d_stream.next_out = (Bytef*)uncompr;
   
    /* MAX_WBITS = 15 */
    if (inflateInit2(&d_stream, MAX_WBITS + 16) != Z_OK)
        return 1;

    while ( (d_stream.total_out < *uncompr_len) && (d_stream.total_in < *compr_len) )
    {
        d_stream.avail_in = d_stream.avail_out = 1;
        if ((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END)
            break;

        if (err != Z_OK)
        {
            if (err == Z_DATA_ERROR)
            {
                d_stream.next_in = (Bytef*)dummy_head;
                d_stream.avail_in = sizeof(dummy_head);
                if ((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK)
                {
                    return 1;
                }
            }
            else
                return 1;
        }
    }

    if (inflateEnd(&d_stream) != Z_OK)
        return 1;

    *uncompr_len = d_stream.total_out;

    return 0;

}

// end of the file


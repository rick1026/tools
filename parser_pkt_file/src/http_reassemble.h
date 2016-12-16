/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
#ifndef __HTTP_REASSEMBLE_H
#define __HTTP_REASSEMBLE_H

#include <semaphore.h>
#include <pthread.h>

#include "tcp_reassemble.h"
#include "beap_hash.h"


#define MAX_SIZE_HTTP_HASH   65536
#define MAX_INDEX_HTTP_HASH  (MAX_SIZE_HTTP_HASH - 1)

#define HTTP_CONN_TIME_OUT    45

typedef enum ENUM_HTTP_METHOD{
    method_none = 0,
    method_get = 1,
    method_post = 2,
    method_resp = 3
}HTTP_METHOD;

typedef enum ENUM_HTTP_CONTENT_TYPE{
    text = 0,
    ntext = 1
}HTTP_CONTENT_TYPE;

typedef enum ENUM_HTTP_STATUS{
    S_DFFAULT = 0,
    S_REQ_HEAD_START = 1,
    S_REQ_HEAD_END = 2,
    S_REQ_END = 3,
    S_RSP_HEAD_START = 4,
    S_RSP_HEAD_END = 5,
    S_RSP_END = 6
}HTTP_STATUS;

typedef struct _stru_tcp_sdu_node{
    unsigned char                 *data;
    unsigned int                  data_len;
    struct _stru_tcp_sdu_node     *next;
}stru_tcpsdu_node;

typedef struct _stru_http_info{
    TCPsessionID      sessid;
    HTTP_STATUS       status;
    char              url[256];
    char              host[256];
    int               method;
    int               req_body_len;
    int               req_head_len;
    int               req_got_len;
    int               rsp_body_len;
    int               rsp_head_len;
    int               rsp_got_len;
    char              content_type[64];
	int               type_text_flag;
    char              rsp_chunk_flag;
    char              rsp_gzip_flag;
    //unsigned long     rsp_gzip_cksum;
    char              rsp_gzip_cksum[8];
    unsigned int      seq_no;
    stru_tcpsdu_node  *sdu_list_up;
    stru_tcpsdu_node  *sdu_list_down;
}stru_http_info;

typedef struct _stru_http_req_header{
    HTTP_METHOD       method;
    //char              UAgent[32];
    char              url[256];
    char              host[256];
    char              content_type[64];
	int               type_text_flag;
    int               head_len;
    int               content_len;
    int               tailer_bingo;
    char              chunk_flag;
    char              gzip_flag;
    char              gzip_cksum[8];
}stru_http_req_head;

typedef struct _stru_http_resp_header{
    char              content_type[64];
    char              chunk_flag;
    char              gzip_flag;
    unsigned char     gzip_cksum[8];
}stru_http_resp_head;

class cls_http_reassemble
{
private:
    sem_t             sem_http_hash;
    pthread_t         hdl_http_hash_timer;
    hash_table        *http_reassemble_tbl;

private:
    int               atox(char*);
    static void       *http_cache_tbl_timer(void*);
    void              do_timer(void);

    int               insert_list(stru_tcpsdu_node **head,unsigned char *data,int data_len);
    int               get_list_data(stru_tcpsdu_node *head,unsigned char *data);
    int               free_list(stru_tcpsdu_node **head);

    
    char analyse_http_resp(unsigned char *data, unsigned int datalen, stru_http_req_head *header);
    char beap_uncompress_new(unsigned char *uncompr, unsigned int *uncompr_len, unsigned char *compr, unsigned int *compr_len);

public:
    cls_http_reassemble();
    ~cls_http_reassemble();

    char analyse_http_req(unsigned char *data, unsigned int datalen, stru_http_req_head *header);

    char do_http_reassemble(TCPsessionID  sess_id,
                      unsigned int  sdu_len,
                      unsigned char *sdu_data,
                      stru_http_req_head *http_header,
                      enum TCPDirection dir,
                      unsigned int  *http_data_len,
                      unsigned char **http_data_buf);

    
    int dechunk_data(unsigned char *data, unsigned int *data_len);
    int unzip_data(unsigned char *data, unsigned int data_len, unsigned char **unzip_buf, unsigned int *unzip_len);

};

#endif


// end of the file

/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *                                                                         *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifndef __HTTP_URL_CACHE_H
#define __HTTP_URL_CACHE_H

#include <semaphore.h>
#include <pthread.h>
#include <list>
#include <vector>

using namespace std;

#include "data_def.h"
#include "beap_hash.h"

#define SIZE_CACHE_HTTP_HASH           1024

typedef vector<stru_ISMS_policy>       VecPly;

typedef struct _stru_http_url
{
    char url[256];
    char host[256];
}stru_http_url;

typedef struct _stru_cache_http_node{
    stru_http_url     key;
    int               type; // text(1), not_text(0)
    char              *txt_content;
    char              filter_flag;
	int               policy_idx;
}stru_cache_http;

unsigned int http_cache_hash_func(void *key);
unsigned char http_cache_comp_func(void *key1, void *key2);
        
class cls_http_url_cache
{
private:
    sem_t             sem_http_cache;
    hash_table        *http_cache_hash;
    pthread_t         hdl_http_cache_timer;

private:
    static void         *http_cache_tbl_timer(void *arg);
    void                do_timer();
        
public:
    cls_http_url_cache();
    ~cls_http_url_cache();

    void lock();
    void unlock();

    int get_http_req_head(const unsigned char *pContent, const unsigned int content_len, stru_http_header *ptr_http_head);
    int get_http_resp_head(const unsigned char *pContent, const unsigned int content_len, stru_http_header *p_http_head);

    void insert_not_text_to_cache(char *url, char *host);
    void insert_text_to_cache(stru_ISMS_policy, char *url, char *host, char *content, int content_len);
    void insert_text_to_cache(int ply_idx, char *url, char *host, char *content, int content_len);
    void insert_text_to_cache(char *url, char *host, char *content, int content_len);


    int do_http_cache(char *host, char *url);
    int do_http_cache(char *host, char *url, stru_cache_http *ret_cache);
	int do_http_cache(stru_http_header http_header, stru_cache_http *ret_cache);
    int do_http_cache(const LLHeadStru *pStruLLHead,
                      const L3HeadStru *pStruL3Head,
                      const TCPHeadStru *pStruTCPHead,
                      unsigned int sip,
                      unsigned short sport,
                      unsigned int dip,
                      unsigned short dport,
                      const unsigned char *pContent,
                      const unsigned int content_len,
                      stru_http_header   http_header,
                      stru_cache_http    *ret_cache
                     );
        
};

#endif

// end of the file
  

/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "http_url_cache.h"

//#define __HTTP_URL_CACHE_LOG

static char http_sufix[][8] = {
    ".xml",
    ".swf",
    ".jpg",
    ".jpeg",
    ".png",
    ".bmp",
    ".gif",
    ".css",
    ".mp3",
    ".wma",
    ".txt",
    ".rar",
    ".flv",
	".iso",
	".avi",
	".xls",
	".doc",
	".txt",
	".pdf",
	".tif",
	".amr",
	".aac",
	".mov",
	".swf",
};
static int size_sufix = sizeof(http_sufix) / 8;


unsigned int http_cache_hash_func(void *key)
{
    unsigned int i = 0, ret = 0;
    for (i = 0; i < sizeof(stru_http_url); i ++)
    {
        ret += *(unsigned char*)((unsigned char*)key + i);
    }

    int idx = (ret & (SIZE_CACHE_HTTP_HASH - 1));
	//printf("http_cache_hash_func(): idx = %u\n", idx);
	return idx;
    //return ret & (SIZE_CACHE_HTTP_HASH - 1);
}

unsigned char http_cache_comp_func(void *key1, void *key2)
{
    return memcmp(key1, key2, sizeof(stru_http_url));
}
 
cls_http_url_cache::cls_http_url_cache()
{
    if (sem_init(&sem_http_cache, 0, 1) == -1)
    {
        printf("sem_init sem_http_cache error, exit!\n");
        exit(1);
    }
    
    if ((http_cache_hash = create_hash(SIZE_CACHE_HTTP_HASH, http_cache_hash_func, http_cache_comp_func)) == NULL)
    {
        printf("conn_hash: create_hash error, exit!\n");
        exit(1);
    }

	printf("cls_http_url_cache(): addr of http_cache_hash = %p\n", http_cache_hash);
    
    pthread_create(&hdl_http_cache_timer, NULL, http_cache_tbl_timer, (void*)this);
}

cls_http_url_cache::~ cls_http_url_cache()
{
}

void* cls_http_url_cache::http_cache_tbl_timer(void *arg)
{
    cls_http_url_cache *pThis = reinterpret_cast<cls_http_url_cache*>(arg);
    
    pThis->do_timer();
}

void   cls_http_url_cache::do_timer()
{
    while(1)
    {
        sleep(5);
        printf("%u, cls_http_url_cache do_timer() running, addr of http_cache_hash = %p!!!\n", time(0), http_cache_hash);
    }
    
}

void cls_http_url_cache::lock()
{
}

void cls_http_url_cache::unlock()
{
}

int cls_http_url_cache::get_http_req_head(const unsigned char *pContent, const unsigned int content_len, stru_http_header *p_http_head)
{
    //printf("get_http_req_head: content: addr=%p, len=%d, content = ((((((%s))))))\n", pContent, content_len, pContent);
    p_http_head->content_type = 1;

    int method = 0;
    // not a GET request, , method=0, return
    if (memcmp(pContent, "GET ", 4) == 0)
    {
        method = p_http_head->method = 1;
    }
    else if (memcmp(pContent, "POST ", 5) == 0)
    {
        method = p_http_head->method = 2;
    }
    else if (memcmp(pContent, "HTTP/", 5) == 0)
    {
        method = p_http_head->method = 3;

		p_http_head->content_type = 1;
        p_http_head->content_length = 0;
        p_http_head->chunk_flag = 0;
        p_http_head->gzip_flag = 0;

        unsigned char *p_type = (unsigned char*)memmem(pContent, content_len, "Content-Type: ", 14);
        if (p_type != NULL)
        {
            unsigned char *p_tailer = (unsigned char*)memmem(p_type, content_len - (p_type - pContent), "\n", 1);
            if (p_tailer != NULL)
            {
                if ((*(p_tailer - 1)) == '\r')
                    p_tailer--;

                unsigned char content_type[64];
                bzero(content_type, sizeof(content_type));
                memcpy(content_type, p_type + 14, p_tailer - p_type - 14);
#ifdef __HTTP_URL_CACHE_LOG
                printf("get content_type: (%s)\n", content_type);
#endif

                if ((strstr((const char*)content_type, "text/html") != NULL) ||
                     (strstr((const char*)content_type, "text/javascript") != NULL) ||
                     (strstr((const char*)content_type, "application/x-gzip") != NULL) ||
                     (strstr((const char*)content_type, "application/x-msgpack") != NULL))
                    p_http_head->content_type = 1;
                else
                    p_http_head->content_type = 0;
            }
        }
        return 0;
    }
    else
    {
#ifdef __HTTP_URL_CACHE_LOG
        printf("get_http_req_head: can't 1111111111 GET, return!!!!\n");
#endif
        return 0;
    }

    bzero(p_http_head, sizeof(stru_http_header));
    p_http_head->method = method;
    p_http_head->content_type = 1;

    // the request packet doesn't contain \n, return
    unsigned char *p_head_tailer = (unsigned char*)memmem(pContent, content_len, "\n", 1);
    if (p_head_tailer == NULL)
    {
#ifdef __HTTP_URL_CACHE_LOG
        printf("get_http_req_head: can't 2222222222 tailer, return!!!!\n");
#endif
        return 0;
    }
    else
    {
#ifdef __HTTP_URL_CACHE_LOG
        printf("get_http_req_head: 22222 find tailer, addr = %p\n", p_head_tailer);
#endif
    }

    int find_len = 0, copy_len = 0;
    find_len = p_head_tailer - pContent;
    //printf("get_http_req_head: find \\n, pos = %p, pcontent = %p, find_len = %d\n", p_head_tailer, pContent, find_len);

    // get the position of http version
    unsigned char *p_http_ver = (unsigned char*)memmem(pContent, find_len, "HTTP/1", 6);
    if (p_http_ver == NULL || p_http_ver > p_head_tailer)
    {
#ifdef __HTTP_URL_CACHE_LOG
        printf("get_http_req_head: can't 3333333333 HTTP, return!!!!\n");
#endif
        return 0;
    }
    else
    {
#ifdef __HTTP_URL_CACHE_LOG
        printf("get_http_req_head: 333333 find HTTP/, addr = %p\n", p_http_ver);
#endif
    }

    // save the url of http request
    unsigned char url[256];
    bzero(url, sizeof(url));

    unsigned char *p_copy_start = NULL;
    if (p_http_head->method == 1)
    {
        p_copy_start = (unsigned char*)pContent + 4;
    }
    else
    {
        p_copy_start = (unsigned char*)pContent + 5;
    }
    copy_len = p_http_ver - p_copy_start;
	if (copy_len >= sizeof(url))
		copy_len = sizeof(url) - 1;
    memcpy(url, pContent + 4, copy_len);
    if (url[copy_len - 1] == ' ')
        url[copy_len - 1] = '\0';

    strncpy(p_http_head->url, (const char*)url, sizeof(url) - 1);
#ifdef __HTTP_URL_CACHE_LOG
    printf("get_http_req_head: get url = <%s>\n", url);
#endif


    // check the type according the url
    {
        // find the first ?
        unsigned char real_url[256];
        bzero(real_url, sizeof(real_url));
        unsigned char *pst_arg = (unsigned char*)strstr((const char*)url, "?");
        if (pst_arg != NULL)
        {
            strncpy((char*)real_url, (const char*)url, pst_arg - url);
#ifdef __HTTP_URL_CACHE_LOG
            printf("get_http_req_head: find parameter start!!!!!!!\n");
#endif
        }
        else
        {
            strncpy((char*)real_url, (const char*)url, strlen((const char*)url));
#ifdef __HTTP_URL_CACHE_LOG
            printf("get_http_req_head: the request has no parameter!!!!\n");
#endif
        }

#ifdef __HTTP_URL_CACHE_LOG
        printf("get_http_req_head: real_url = (%s), len = %d\n", real_url, strlen((const char*)real_url));
#endif

        unsigned char *pst_point = (unsigned char*)strrchr((const char*)real_url, '.');
        if (pst_point != NULL)
        {
            int i = 0;
            unsigned char real_suffix[16] = {0};
            copy_len = strlen((const char*)real_url) - (int)(pst_point - real_url);
            
            //printf("get_http_req_head: copy_len = %d, size_sufix = %d, (%s)\n", copy_len, size_sufix, pst_point);
            memcpy(real_suffix, pst_point, copy_len);
            for (i = 0; i < size_sufix; i++)
            {
                if (strcmp((const char*)real_suffix, http_sufix[i]) == 0)
                {
#ifdef __HTTP_URL_CACHE_LOG
                    printf("get_http_req_head: real_url bingo: %s\n", http_sufix[i]);
#endif
                    break;
                }
                else
                {
                    //printf("get_http_req_head: real_url not bingo, go on matching\n");
                }
            }

            if (i < size_sufix)
                p_http_head->content_type = 0;
        }
        else
        {
#ifdef __HTTP_URL_CACHE_LOG
            printf("get_http_req_head: the requested-url has no suffix!!!\n");
#endif
        }
    }

    // the request packet doesn't contain Host header, return
    unsigned char *p_host = (unsigned char*)memmem(pContent, content_len, "Host: ", 6);
    if (p_host == NULL)
    {
#ifdef __HTTP_URL_CACHE_LOG
        printf("get_http_req_head: 44444444444 HOST error!!!!\n");
#endif
        return 0;
    }
    else
    {
#ifdef __HTTP_URL_CACHE_LOG
        printf("get_http_req_head: find HOST in packet!!!!\n");
#endif
    }

    find_len = content_len - (p_host - pContent);
    p_head_tailer = (unsigned char*)memmem(p_host, find_len, "\n", 1);
    unsigned char host_line[256] = {0};
    unsigned char *p_host_tailer = (unsigned char*)memmem((void*)p_host, find_len, "\n", 1);
    if (p_host_tailer == NULL)
    {
#ifdef __HTTP_URL_CACHE_LOG
        printf("get_http_req_head: find no tailer for host, return!!!!\n");
#endif
        return 0;
    }
    else
    {
        //printf("get_http_req_head: find tailer for HOST, addr = %p, go on!!!!\n", p_host_tailer);
    }

    if (*(p_host_tailer - 1) == '\r')
        p_host_tailer--;
    
    copy_len = p_host_tailer - p_host - 6;
    memcpy(p_http_head->host, p_host + 6, copy_len);
    //printf("get_http_req_head: copy_len = %d, get host = <%s>\n", copy_len, p_http_head->host);

    // the request need tcp_reassemble, return
    if (!memmem(pContent, content_len, "\r\n\r\n", 4))
        return 0;
}

int cls_http_url_cache::get_http_resp_head(const unsigned char *pContent, const unsigned int content_len, stru_http_header *p_http_head)
{
    // not a GET req, return
    if (memcmp(pContent, "HTTP/", 5))
    {
        return 0;
    }

    unsigned char *p_head_tailer = (unsigned char*)memmem(pContent, content_len, "\r\n\r\n", 4);
    if (p_head_tailer == NULL)
        return 0;
}

int cls_http_url_cache::do_http_cache(char *host, char *url)
{
    if (http_cache_hash == NULL)
    {
        printf("do_http_cache: the cache_http_hash hasn't been created!\n");
        return 0;
    }

	//printf("do_http_cache: addr of http_cache_hash = %p\n", http_cache_hash);
#ifdef __HTTP_URL_CACHE_LOG
	printf("do_http_cache: host = %s, url = %s\n", host, url);
#endif

    stru_http_url  cache_key;
    bzero(&cache_key, sizeof(cache_key));
    strcpy(cache_key.url, url);
    strcpy(cache_key.host, host);
    
    hash_bucket *p_bucket = find_hash(http_cache_hash, &cache_key);

    if (p_bucket == NULL)
    {
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache: find no item in cache_http_hash, return!\n");
#endif
        return 0;
    }

    stru_cache_http *cache_item = (stru_cache_http*)(p_bucket->content);
	printf("cache_item->type = %d\n", cache_item->type);

	printf("do_http_cache(): p_bucket: %p, cache_item: %p, policy_idx = %d\n", p_bucket, cache_item, cache_item->policy_idx);

    if (cache_item->type == 0)
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache: do_http_url_cache, cache_type = 0, return 1!!!!\n");
#endif
        return 1;
	}

    //if (cache_item->type == 1 && cache_item->vector_ply.empty())
    if (cache_item->type == 1 && ((cache_item->policy_idx) == -1))
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache: do_http_url_cache, cache_type = 1 but no policy, return 2!!!!\n");
#endif
        return 2;
	}

    if (cache_item->type == 1 && ((cache_item->policy_idx) == 1))
	{
		return 3;
	}

    if (cache_item->filter_flag)
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache: do_http_url_cache, cache_type = 1 fitler_flag == 1, return 3!!!!\n");
#endif
        return 3;
	}

    return 0;
}

int cls_http_url_cache::do_http_cache(char *host, char *url, stru_cache_http *ret_cache)
{
    if (http_cache_hash == NULL)
    {
        printf("do_http_cache: the cache_http_hash hasn't been created!\n");
        return 0;
    }

#ifdef __HTTP_URL_CACHE_LOG
	printf("do_http_cache 222: host = %s, url = %s\n", host, url);
#endif

    stru_http_url  cache_key;
    bzero(&cache_key, sizeof(cache_key));
    strcpy(cache_key.url, url);
    strcpy(cache_key.host, host);
    
    hash_bucket *p_bucket = find_hash(http_cache_hash, &cache_key);

    if (p_bucket == NULL)
    {
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 222: find no item in cache_http_hash, return!\n");
#endif
        return 0;
    }

    stru_cache_http *cache_item = (stru_cache_http*)(p_bucket->content);
    memcpy(ret_cache, cache_item, sizeof(stru_cache_http));

#ifdef __HTTP_URL_CACHE_LOG
	printf("do_http_cache 222: p_bucket: %p, cache_item: %p, policy_idx = %d\n", p_bucket, cache_item, cache_item->policy_idx);
#endif

    if (cache_item->type == 0)
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 222: do_http_url_cache, cache_type = 0, return 1!!!!\n");
#endif
        return 1;
	}

    if (cache_item->type == 1 && ((cache_item->policy_idx) == -1))
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 222: do_http_url_cache, cache_type = 1 but no policy, return 2!!!!\n");
#endif
        return 2;
	}

    if (cache_item->type == 1 && ((cache_item->policy_idx) == 1))
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 222: do_http_url_cache, cache_type = 1 with log policy, return 3!!!!\n");
#endif
		return 3;
	}

    if (cache_item->filter_flag)
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache: do_http_url_cache 222, cache_type = 1 fitler_flag == 1, return 3!!!!\n");
#endif
        return 3;
	}
	return 0;
}

int cls_http_url_cache::do_http_cache(stru_http_header http_header, stru_cache_http *ret_cache)
{
    if (http_cache_hash == NULL)
    {
        printf("do_http_cache: the cache_http_hash hasn't been created!\n");
        return 0;
    }

#ifdef __HTTP_URL_CACHE_LOG
	printf("do_http_cache 333: host = %s, url = %s\n", http_header.host, http_header.url);
#endif

    stru_http_url  cache_key;
    bzero(&cache_key, sizeof(cache_key));
    strcpy(cache_key.url, http_header.url);
    strcpy(cache_key.host, http_header.host);
    
    hash_bucket *p_bucket = find_hash(http_cache_hash, &cache_key);

    if (p_bucket == NULL)
    {
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 333: find no item in cache_http_hash, return!\n");
#endif
        return 0;
    }

    stru_cache_http *cache_item = (stru_cache_http*)(p_bucket->content);
    memcpy(ret_cache, cache_item, sizeof(stru_cache_http));

#ifdef __HTTP_URL_CACHE_LOG
	printf("do_http_cache 333: p_bucket: %p, cache_item: %p, type = %d, policy_idx = %d\n", 
           p_bucket, cache_item, cache_item->type, cache_item->policy_idx);
#endif

    if (ret_cache->type == 0)
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 333: do_http_url_cache, cache_type = 0, return 1!!!!\n");
#endif
        return 1;
	}

    if (ret_cache->type == 1 && ((ret_cache->policy_idx) == -1))
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 333: do_http_url_cache, cache_type = 1 but no policy, return 2!!!!\n");
#endif
        return 2;
	}

    if (ret_cache->type == 1 && (ret_cache->policy_idx == 1))
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 333: do_http_url_cache, cache_type = 1 with log policy, return 3!!!!\n");
#endif
		return 3;
	}

    if (ret_cache->filter_flag)
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 333: do_http_url_cache, cache_type = 1 fitler_flag == 1, return 4!!!!\n");
#endif
        return 3;
	}

    return 0;
}

int cls_http_url_cache::do_http_cache(const LLHeadStru *pStruLLHead,
                  const L3HeadStru *pStruL3Head,
                  const TCPHeadStru *pStruTCPHead,
                  unsigned int sip,
                  unsigned short sport,
                  unsigned int dip,
                  unsigned short dport,
                  const unsigned char *pContent,
                  const unsigned int content_len,
                  stru_http_header   http_header,
                  stru_cache_http    *ret_cache)
{
    if (http_cache_hash == NULL)
    {
        printf("do_http_cache: the cache_http_hash hasn't been created!\n");
        return 0;
    }

#ifdef __HTTP_URL_CACHE_LOG
	printf("do_http_cache 444: host = %s, url = %s\n", http_header.host, http_header.url);
#endif

    stru_http_url  cache_key;
    bzero(&cache_key, sizeof(cache_key));
    strcpy(cache_key.url, http_header.url);
    strcpy(cache_key.host, http_header.host);
    
    hash_bucket *p_bucket = find_hash(http_cache_hash, &cache_key);
    if (p_bucket == NULL)
    {
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 444: find no item in cache_http_hash, return!\n");
#endif
        return 0;
    }

    stru_cache_http *cache_item = (stru_cache_http*)(p_bucket->content);
    memcpy(ret_cache, cache_item, sizeof(stru_cache_http));

#ifdef __HTTP_URL_CACHE_LOG
	printf("do_http_cache 444: p_bucket: %p, cache_item: %p, type = %d, policy_idx = %d\n", 
           p_bucket, cache_item, cache_item->type, cache_item->policy_idx);
#endif

    if (ret_cache->type == 0)
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 444: do_http_url_cache, cache_type = 0, return 1!!!!\n");
#endif
        return 1;
	}

    if (ret_cache->type == 1 && ((ret_cache->policy_idx) == -1))
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 444: do_http_url_cache, cache_type = 1 but no policy, return 2!!!!\n");
#endif
        return 2;
	}

    if (ret_cache->type == 1 && (ret_cache->policy_idx == 1))
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 444: do_http_url_cache, cache_type = 1 with log policy, return 3!!!!\n");
#endif
		return 3;
	}

    if (ret_cache->filter_flag)
	{
#ifdef __HTTP_URL_CACHE_LOG
        printf("do_http_cache 444: do_http_url_cache, cache_type = 1 fitler_flag == 1, return 4!!!!\n");
#endif
        return 3;
	}

    return 0;
}


void cls_http_url_cache::insert_not_text_to_cache(char *url, char *host)
{
    hash_bucket *p_bucket = (hash_bucket*)calloc(1, sizeof(hash_bucket));
    if (p_bucket == NULL)
        return ;

#ifdef __HTTP_URL_CACHE_LOG
	printf("insert_not_text_to_cache: host = %s, url = %s\n", host, url);
#endif

    stru_cache_http *p_cache = (stru_cache_http*)calloc(1, sizeof(stru_cache_http));
    strcpy(p_cache->key.url, url);
    strcpy(p_cache->key.host, host);
    p_cache->type = 0;
    p_cache->txt_content = NULL;
    p_cache->filter_flag = 0;
	//p_cache->vector_ply.clear();
	p_cache->policy_idx = -1;

    p_bucket->content = (void*)p_cache;
    p_bucket->key = &(p_cache->key);

    sem_wait(&sem_http_cache);
    insert_hash(http_cache_hash, p_bucket);
    sem_post(&sem_http_cache);
}

void cls_http_url_cache::insert_text_to_cache(stru_ISMS_policy policy, char *url, char *host, char *content, int content_len)
{
    hash_bucket *p_bucket = (hash_bucket*)calloc(1, sizeof(hash_bucket));
    if (p_bucket == NULL)
        return ;

#ifdef __HTTP_URL_CACHE_LOG
	printf("insert_text_to_cache: host = %s, url = %s\n", host, url);
#endif

    stru_cache_http *p_cache = (stru_cache_http*)calloc(1, sizeof(stru_cache_http));
    strcpy(p_cache->key.url, url);
    strcpy(p_cache->key.host, host);
    p_cache->type = 1;
    p_cache->filter_flag = 0;
	//p_cache->vector_ply.clear();
	//p_cache->vector_ply.push_back(policy);
	p_cache->policy_idx = 1;

    p_cache->txt_content = (char*)calloc(1, content_len+1);
	memcpy(p_cache->txt_content, content, content_len);

    p_bucket->content = (void*)p_cache;
    p_bucket->key = &(p_cache->key);

	//printf("insert_text_to_cache(): pbucket: %p, cache: %p\n", p_bucket, p_cache);

    sem_wait(&sem_http_cache);
    insert_hash(http_cache_hash, p_bucket);
    sem_post(&sem_http_cache);
}

void cls_http_url_cache::insert_text_to_cache(char *url, char *host, char *content, int content_len)
{
    hash_bucket *p_bucket = (hash_bucket*)calloc(1, sizeof(hash_bucket));
    if (p_bucket == NULL)
        return ;

#ifdef __HTTP_URL_CACHE_LOG
	printf("insert_text_to_cache: host = %s, url = %s, bingo no rule\n", host, url);
#endif

    stru_cache_http *p_cache = (stru_cache_http*)calloc(1, sizeof(stru_cache_http));
    strcpy(p_cache->key.url, url);
    strcpy(p_cache->key.host, host);
    p_cache->type = 1;
    p_cache->filter_flag = 0;
	//p_cache->vector_ply.clear();
	//p_cache->vector_ply.push_back(policy);
	p_cache->policy_idx = -1;

    p_cache->txt_content = (char*)calloc(1, content_len+1);
	memcpy(p_cache->txt_content, content, content_len);

    p_bucket->content = (void*)p_cache;
    p_bucket->key = &(p_cache->key);


    sem_wait(&sem_http_cache);
    insert_hash(http_cache_hash, p_bucket);
    sem_post(&sem_http_cache);
}


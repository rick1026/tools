/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *                                                                         *
 ***************************************************************************/
#include <stdio.h>
#include <stdlib.h>

#include "conn_hash_cache.h"

//#define __CONN_HASH_CACHE_LOG
#if 0
unsigned int conn_hash_func(void *key)
{
    unsigned int i = 0, ret = 0;
#if 0
	// modified on 20150807
    for (i = 0; i < sizeof(TCPsessionID); i ++)
    {
		//printf("%02x\n", *((unsigned char*)key + i));
        ret += *((unsigned char*)((unsigned char*)key + i));
    }
	//printf("ret = %u\n", ret);
#endif

	for (i = 2; i < sizeof(TCPsessionID); i += 2)
	{
		ret += *(unsigned short*)(key + i);
	}

    return ret & MAX_INDEX_CONN_HASH;
}

unsigned char conn_comp_func(void *key1, void *key2)
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

#endif

cls_conn_hash_cache::cls_conn_hash_cache()
{
    if (sem_init(&sem_conn_hash, 0, 1) == -1)
    {
        printf("sem_init sem_conn_hash error, exit!\n");
        exit(1);
    }
    
//    if ((cache_conn_hash = create_hash(SIZE_CACHE_CONN_HASH, conn_hash_func, conn_comp_func)) == NULL)
//    {
//        printf("conn_hash: create_hash error, exit!\n");
//        exit(1);
//    }

    //printf("cls_conn_hash_cache(): addr of conn_hash = %p, sizeof(stru_conn_node) = %d\n", cache_conn_hash, sizeof(stru_conn_node));
    
    pthread_create(&hdl_conn_timer_thr, NULL, conn_tbl_timer, (void*)this);
}

cls_conn_hash_cache::~ cls_conn_hash_cache()
{
}

void cls_conn_hash_cache::lock(void)
{
    sem_wait(&sem_conn_hash);
}

void cls_conn_hash_cache::unlock(void)
{
    sem_post(&sem_conn_hash);
}

stru_hash_node* cls_conn_hash_cache::do_conn_hash_cache(hash_table *cache_conn_hash,TCPsessionID sess_id)
{
#ifdef __CONN_HASH_CACHE_LOG
    printf("do_conn_hash_cache: sip = %u, dip = %u, sport = %d, dport = %d, cache_conn_hash: %p\n",
           sess_id.src_ip, sess_id.dst_ip, sess_id.src_port, sess_id.dst_port, cache_conn_hash);
#endif

	/*
    if (cache_conn_hash == NULL)
    {
        printf("do_conn_hash_cache: the cache_conn_hash hasn't been created!\n");
        return NULL;
    }
	*/

	//printf("do_conn_hash_cache: addr of cache_conn_hash = %p\n", cache_conn_hash);

    //sem_wait(&sem_conn_hash);
    hash_bucket *p_bucket = find_hash(cache_conn_hash, &sess_id);
    if (p_bucket == NULL)
    {
#ifdef __CONN_HASH_CACHE_LOG
        printf("do_conn_hash_cache: find no item in hash, return!\n");
#endif
        return NULL;
    }

    //stru_conn_node *conn = (stru_conn_node*)(p_bucket->content);
    return  (stru_hash_node*)(p_bucket->content);

    //return conn;
}

void cls_conn_hash_cache::insert_not_text_to_conn(hash_table *cache_conn_hash,TCPsessionID sess_id, stru_http_header http_head, ENUM_PKT_ACTION action)
{
#ifdef __CONN_HASH_CACHE_LOG
    printf("insert_not_text_to_conn: sip = %u, dip = %u, sport = %d, dport = %d\n",
           sess_id.src_ip, sess_id.dst_ip, sess_id.src_port, sess_id.dst_port);
#endif

    hash_bucket *p_bucket = (hash_bucket*)calloc(1, sizeof(hash_bucket));
    if (p_bucket == NULL)
        return;
    
    stru_hash_node *hash_node = (stru_hash_node*)calloc(1, sizeof(stru_hash_node));
    if (hash_node == NULL)
    {
        free(p_bucket);
        p_bucket = NULL;
        return;
    }
    stru_conn_node *p_conn = (stru_conn_node*)calloc(1, sizeof(stru_conn_node));
	if (p_conn == NULL)
    {
        free(p_bucket);
		free(hash_node);
        p_bucket = NULL;
        return;
    }
	hash_node->conn_node = p_conn;

    hash_node->sess_id = sess_id;
    p_conn->action = action;
    p_conn->ply_BMap.clear();
	

    if (http_head.method == 1 || http_head.method == 2)
    {
        if (http_head.url[0] != '\0')
            strcpy(p_conn->url, http_head.url);

        if (http_head.host[0] != '\0')
            strcpy(p_conn->host, http_head.host);
    }
    
    p_bucket->content = (void*)hash_node;
    p_bucket->key = &(hash_node->sess_id);

    insert_hash(cache_conn_hash, p_bucket);
}

void cls_conn_hash_cache::insert_text_to_conn(hash_table *cache_conn_hash,TCPsessionID sess_id, stru_http_header http_head, ENUM_PKT_ACTION action)
{
    hash_bucket *p_bucket = (hash_bucket*)calloc(1, sizeof(hash_bucket));
    if (p_bucket == NULL)
        return;
	stru_hash_node *hash_node = (stru_hash_node*)calloc(1, sizeof(stru_hash_node));
    if (hash_node == NULL)
    {
        free(p_bucket);
        p_bucket = NULL;
        return;
    }
    stru_conn_node *p_conn = (stru_conn_node*)calloc(1, sizeof(stru_conn_node));
	if (p_conn == NULL)
    {
        free(p_bucket);
		free(hash_node);
        p_bucket = NULL;
        return;
    }
	hash_node->conn_node = p_conn;

    hash_node->sess_id = sess_id;
    p_conn->action = action;
    p_conn->ply_BMap.clear();
    
    if (http_head.method == 1 || http_head.method == 2)
    {
        if (http_head.url[0] != '\0')
            strcpy(p_conn->url, http_head.url);

        if (http_head.host[0] != '\0')
            strcpy(p_conn->host, http_head.host);
    }
    p_bucket->content = (void*)hash_node;
    p_bucket->key = &(hash_node->sess_id);
    insert_hash(cache_conn_hash, p_bucket);
}

stru_hash_node *cls_conn_hash_cache::insert_new_conn(hash_table *cache_conn_hash,TCPsessionID sess_id, stru_http_header http_head)
{
    hash_bucket *p_bucket = (hash_bucket*)calloc(1, sizeof(hash_bucket));
    if (p_bucket == NULL)
        return NULL;
	stru_hash_node *hash_node = (stru_hash_node*)calloc(1, sizeof(stru_hash_node));
    if (hash_node == NULL)
    {
        free(p_bucket);
        p_bucket = NULL;
        return NULL;
    }
    stru_conn_node *p_conn = (stru_conn_node*)calloc(1, sizeof(stru_conn_node));
	if (p_conn == NULL)
    {
        free(p_bucket);
		free(hash_node);
        p_bucket = NULL;
        return NULL;
    }
	hash_node->conn_node = p_conn;

	hash_node->sess_id = sess_id;
    p_conn->action = PKT_DEAL;
    p_conn->ply_BMap.clear();

    if (http_head.method == 1 || http_head.method == 2)
    {
        if (http_head.url[0] != '\0')
            strcpy(p_conn->url, http_head.url);

        if (http_head.host[0] != '\0')
            strcpy(p_conn->host, http_head.host);
    }

    p_bucket->content = (void*)hash_node;
    p_bucket->key = &(hash_node->sess_id);
    insert_hash(cache_conn_hash, p_bucket);

    return hash_node;
}


void* cls_conn_hash_cache::conn_tbl_timer(void *arg)
{
    cls_conn_hash_cache *pThis = reinterpret_cast<cls_conn_hash_cache*>(arg);
    
    pThis->do_timer();
}

void   cls_conn_hash_cache::do_timer()
{
    while(1)
    {
        sleep(5);
        //printf("%u, cls_conn_hash_cache do_timer() running, addr of conn_hash = %p!!!\n", time(0), cache_conn_hash);
    }
    
}

void cls_conn_hash_cache::set_conn_BMap_by_rulelist(stru_conn_node *p_conn, ListRuleInfo& rule_list)
{
    ListRuleInfo::iterator p = rule_list.begin();
    while (p != rule_list.end())
    {
        stru_prule_position coordinate = *p++;
        MapPolicyBMap::iterator ptr = p_conn->ply_BMap.find(coordinate.ply_idx);
#ifdef __CONN_HASH_CACHE_LOG
        printf("set_conn_BMap: match policy[%d].rule[%d], set bit\n", coordinate.ply_idx, coordinate.rule_idx);
#endif
        if (ptr != p_conn->ply_BMap.end())
        {
            ClsBMap& BMap = ptr->second;
            BMap.setbit(coordinate.rule_idx);
#ifdef __CONN_HASH_CACHE_LOG
			printf("after set, BMap: %s\n", BMap.getmap().c_str());
#endif
        }
        else
        {
            ClsBMap BMap;
            BMap.setbit(coordinate.rule_idx);
            p_conn->ply_BMap.insert(pair<int, ClsBMap>(coordinate.ply_idx, BMap));
#ifdef __CONN_HASH_CACHE_LOG
			printf("after set, BMap: %s\n", BMap.getmap().c_str());
#endif
        }
    }
}

int cls_conn_hash_cache::check_BMap_by_conn(stru_conn_node *pconn, vector<stru_ISMS_policy>& vector_ply)
{
    int highest_priority = 0x7fffffff, index = -1;
    MapPolicyBMap::iterator ptr = pconn->ply_BMap.begin();
    for (; ptr != pconn->ply_BMap.end(); ptr++)
    {
        int ply_idx = ptr->first;

#ifdef __CONN_HASH_CACHE_LOG
		printf("check_BMap_by_conn: policy index = %d, level = %d\n", ply_idx, vector_ply[ply_idx].Level);
#endif
        ClsBMap& real_map = ptr->second;
        ClsBMap  expect_map = vector_ply[ply_idx].BMap;

#ifdef __CONN_HASH_CACHE_LOG
		printf("real_map: %s\n", real_map.getmap().c_str());
		printf("expect_map: %s\n", expect_map.getmap().c_str());
#endif
        if (expect_map == real_map)
        {
#ifdef __CONN_HASH_CACHE_LOG
			printf("expect_map == real_map...........\n");
#endif
            if (vector_ply[ply_idx].Level < highest_priority)
            {
                index = ply_idx;
                highest_priority = vector_ply[ply_idx].Level;
            }
        }
    }

    return index;
}



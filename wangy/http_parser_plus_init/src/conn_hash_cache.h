/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *                                                                         *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
#ifndef __CONN_HASH_CACHE_H
#define __CONN_HASH_CACHE_H

#include <list>
#include <vector>
#include <string>
#include <map>
#include "struct.h"

using namespace std;

#include "beap_hash.h"
#include "tcp_reassemble.h"
#include "data_def.h"

// SIZE_CACHE_CONN_HASH = 2^20
#define SIZE_CACHE_CONN_HASH           1048576
#define MAX_INDEX_CONN_HASH            (SIZE_CACHE_CONN_HASH - 1)

// save an connection an the action to the packets of the connection
unsigned int conn_hash_func(void *key);
unsigned char conn_comp_func(void *key1, void *key2);

class cls_conn_hash_cache
{
    private:
        sem_t             sem_conn_hash;
        //hash_table        *cache_conn_hash;
        pthread_t           hdl_conn_timer_thr;

    private:
        static void         *conn_tbl_timer(void *arg);
        void                do_timer();

    public:
        cls_conn_hash_cache();
        ~cls_conn_hash_cache();

        void lock(void);
        void unlock(void);

        stru_hash_node* do_conn_hash_cache(hash_table *cache_conn_hash,TCPsessionID sess_id);

        stru_hash_node* insert_new_conn(hash_table *cache_conn_hash,TCPsessionID sess_id, stru_http_header http_head);
        void insert_not_text_to_conn(hash_table *cache_conn_hash,TCPsessionID sess_id, stru_http_header http_head, ENUM_PKT_ACTION action);
        void insert_text_to_conn(hash_table *cache_conn_hash,TCPsessionID sess_id, stru_http_header http_head, ENUM_PKT_ACTION action);
        
        void set_conn_BMap_by_rulelist(stru_conn_node *p_conn, ListRuleInfo& rule_list);
        int  check_BMap_by_conn(stru_conn_node *pconn, vector<stru_ISMS_policy>&,char *keyword,int keyword_len);

};


#endif

// end of the file

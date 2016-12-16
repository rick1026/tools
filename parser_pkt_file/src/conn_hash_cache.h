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

using namespace std;

#include "beap_hash.h"
#include "tcp_reassemble.h"
#include "data_def.h"

// SIZE_CACHE_CONN_HASH = 2^20
#define SIZE_CACHE_CONN_HASH           1048576
#define MAX_INDEX_CONN_HASH            (SIZE_CACHE_CONN_HASH - 1)

typedef enum PKT_ACTION{
    PKT_RET = 0,
    PKT_RST = 1,
    PKT_DEAL = 2
}ENUM_PKT_ACTION;

// save an connection an the action to the packets of the connection
typedef struct stru_cache_conn_node{
    TCPsessionID      sess_id;
    char              url[256];
    char              host[256];

    ENUM_PKT_ACTION   action;
	int               verdict_flag;
	MapPlyBMap        ply_BMap; // key is policy_index, content is the BMap of every policy
	unsigned long     do_match_time;
}stru_conn_node;

unsigned int conn_hash_func(void *key);
unsigned char conn_comp_func(void *key1, void *key2);

class cls_conn_hash_cache
{
    private:
        sem_t             sem_conn_hash;
        hash_table        *cache_conn_hash;
        pthread_t           hdl_conn_timer_thr;

    private:
        static void         *conn_tbl_timer(void *arg);
        void                do_timer();

    public:
        cls_conn_hash_cache();
        ~cls_conn_hash_cache();

        void lock(void);
        void unlock(void);

        stru_conn_node* do_conn_hash_cache(TCPsessionID sess_id);

        stru_conn_node* insert_new_conn(TCPsessionID sess_id, stru_http_header http_head);
        void insert_not_text_to_conn(TCPsessionID sess_id, stru_http_header http_head, ENUM_PKT_ACTION action);
        void insert_text_to_conn(TCPsessionID sess_id, stru_http_header http_head, ENUM_PKT_ACTION action);
        
        void set_conn_BMap_by_rulelist(stru_conn_node *p_conn, ListRuleInfo& rule_list);
        int  check_BMap_by_conn(stru_conn_node *pconn, vector<stru_ISMS_policy>&);

};


#endif

// end of the file

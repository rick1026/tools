/***************************************************************************
 *   Copyright (C) 2005 by hg                                              *
 *   brianhe@bupt.edu.cn                                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef __BEAP_HASH
#define __BEAP_HASH

//#define MAX_HASH_SIZE   16384
#define MAX_HASH_SIZE     2147483648

typedef unsigned int(* t_hash_func)(void *) ;
typedef unsigned char(* t_comp_func)(void *, void *) ;

struct stru_hash_bucket;

typedef struct{
struct stru_hash_bucket * prev_hash;
struct stru_hash_bucket * next_hash;
}hash_ptr;
 
typedef struct stru_hash_bucket{
void *		key;
void *		content;
hash_ptr	ptr;
}hash_bucket;
 
typedef struct{
hash_bucket  	**hashtable;
int 		nr_entries;
int		tbl_size;
t_hash_func	hash_func;
t_comp_func	comp_func;
}hash_table;

// canceled by zhangjl from 3474 on 20110831

hash_table * create_hash(int , t_hash_func , t_comp_func );
void delete_hash(hash_table *);
void delete_hash_keep_content(hash_table *);
void insert_hash(hash_table * , hash_bucket * );
void remove_hash(hash_table * , hash_bucket * );
hash_bucket * find_hash(hash_table * , void* );

#endif
// __BEAP_HASH

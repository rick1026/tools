/***************************************************************************
 *   Copyright (C) 2005 by hg                                              *
 *   brianhe@bupt.edu.cn                                                   *
 *                                                                         *
 ***************************************************************************/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "beap_hash.h"

hash_table * create_hash(int size, \
			t_hash_func hash_func, \
			t_comp_func comp_func)
{
  hash_table 	*tbl;
  int		i;

  if (size < 0 || size > MAX_HASH_SIZE)
  {	  
	  return NULL;
  }
  if (hash_func == 0)
  {
  	return NULL;
  }	
  tbl = (hash_table*)calloc(1, sizeof(hash_table));
  if ((tbl->hashtable = (hash_bucket**)calloc(size, sizeof(hash_bucket *))) == NULL)
  {
  	return NULL;
  }

  memset((void*)tbl->hashtable, 0, size * sizeof(hash_bucket *));
  
  tbl->nr_entries = 0;
  tbl->tbl_size = size;
  tbl->hash_func = hash_func;
  tbl->comp_func = comp_func;
  return tbl;
} 
void delete_hash(hash_table *tbl)
{
  int i;
  hash_bucket *prev,*next;
  
//   printf("\n delete_hash");
//   printf("\n delete_hash");
  
  for (i = 0; i < tbl->tbl_size; i ++)
	if ((prev = tbl->hashtable[i]) == NULL)
		continue;
	else
		while(prev){
			next = prev->ptr.next_hash;
			free(prev->content);
			free(prev);
			prev = next;
		}
  tbl->nr_entries = 0;
  free(tbl->hashtable);
}

void delete_hash_keep_content(hash_table *tbl)
{
  int i;
  hash_bucket *prev,*next;
  
  for (i = 0; i < tbl->tbl_size; i ++)
	if ((prev = tbl->hashtable[i]) == NULL)
		continue;
	else
		while(prev){
			next = prev->ptr.next_hash;
			free(prev);
			prev = next;
		}
  tbl->nr_entries = 0;
  free(tbl->hashtable);
}


void insert_hash(hash_table * tbl, hash_bucket * elem)
{
  int depth;

  int ix = tbl -> hash_func(elem->key);
  //printf("insert_hash: the index to be insert = %d\n", ix);
  
  hash_bucket ** base = &tbl->hashtable[ix];
  hash_bucket * ptr = *base;
  hash_bucket * prev = NULL;
  depth = 0;
  tbl->nr_entries++;
  while(ptr && tbl -> comp_func(ptr->key, elem->key)){
	base = &ptr->ptr.next_hash;
	prev = ptr;
	ptr = *base;
	depth ++;
  }
  elem->ptr.next_hash = ptr;
  elem->ptr.prev_hash = prev;
  if(ptr){
	ptr->ptr.prev_hash = elem;
  }
  *base = elem;
	// printf("bucket %d depth %d\n", ix, depth);
}

void remove_hash(hash_table * tbl, hash_bucket * elem)
{
  //printf("remove_hash, addr_tbl = %p\n", tbl);
  //   printf("\n remove_hash");
  hash_bucket * next = elem->ptr.next_hash;
  hash_bucket * prev = elem->ptr.prev_hash;

  tbl->nr_entries--;
  if(next)
	next->ptr.prev_hash = prev;
  if(prev)
	prev->ptr.next_hash = next;
  else {
	int ix = tbl -> hash_func(elem->key);
	tbl->hashtable[ix] = next;
  }
}

hash_bucket * find_hash(hash_table * tbl, void* pos)
{
	unsigned int ix = tbl -> hash_func(pos);

	//printf("find_hash, addr_tbl = %p, addr_pos: %p, ix = %u\n", tbl, pos, ix);
	hash_bucket * ptr = tbl->hashtable[ix];
	//printf("find_hash, addr_tbl = %p, addr_pos: %p, ix = %u, addr of index[%d] = %p\n", tbl, pos, ix, ix, ptr);
	while(ptr){
		if(tbl -> comp_func(ptr->key, pos) == 0)
			break;
		ptr = ptr->ptr.next_hash;
	}
	return ptr;
}


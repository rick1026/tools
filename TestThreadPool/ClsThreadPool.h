/*
 * ClsThreadPool.h
 *
 *  Created on: Jul 19, 2016
 *      Author: zhangjl
 */

#ifndef CLSTHREADPOOL_H_
#define CLSTHREADPOOL_H_

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<pthread.h>
#include<sys/types.h>
#include<memory.h>
#include<errno.h>
#include<signal.h>

typedef struct _thread_worker_t
{
	void *(*process)(void *arg);      // the proc function of the thread
	void *arg;                        // the parameter of the proc function
	struct _thread_worker_t *next;    // the next thread worker node
}thread_worker_t;

typedef struct
{
	pthread_mutex_t queue_lock;       // mutex locker
	pthread_cond_t  queue_ready;      // conditional locker

	thread_worker_t *head;            // the header of the worker list
	bool            isdestroy;        // if the thread has been destoryed
	pthread_t       *threadid;        // the array of thread id, allocate
	int             reqnum;           // the number of thread will be created
	int             num;              // the real number of thread was created
	int             queue_size;       // the size of current work queue

}thread_pool_t;

extern int thread_pool_init(thread_pool_t **pool, int num);
extern int thread_pool_add_worker(thread_pool_t *pool, void *(*process)(void *arg), void *arg);
extern int thread_pool_keepalive(thread_pool_t *pool);
extern int thread_pool_destroy(thread_pool_t *pool);


class ClsThreadPool {
public:
	ClsThreadPool();
	virtual ~ClsThreadPool();
};

#endif /* CLSTHREADPOOL_H_ */

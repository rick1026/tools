/*
 * ClsThreadPool.cpp
 *
 *  Created on: Jul 19, 2016
 *      Author: zhangjl
 */

#include "ClsThreadPool.h"

static int thread_create_detach(thread_pool_t *pool, int idx);
static void *thread_routine(void *arg);

ClsThreadPool::ClsThreadPool() {
	// TODO Auto-generated constructor stub

}

ClsThreadPool::~ClsThreadPool() {
	// TODO Auto-generated destructor stub
}


int thread_pool_init(thread_pool_t **pool, int num)
{
	int idx = 0, ret = 0;

	// allocate memory for thread pool
	*pool = (thread_pool_t*)calloc(1, sizeof(thread_pool_t));
	if (NULL == *pool)
	{
		return -1;
	}

	// initialize the thread pool
	pthread_mutex_init(&((*pool)->queue_lock), NULL);
	pthread_cond_init(&((*pool)->queue_ready), NULL);

	(*pool)->head = NULL;
	(*pool)->reqnum = num;
	(*pool)->queue_size = 0;
	(*pool)->isdestroy = false;
	(*pool)->threadid = (pthread_t*)calloc(1, num * sizeof(pthread_t));

	if (NULL == (*pool)->threadid)
	{
		free(*pool);
		(*pool) = NULL;

		return -1;
	}

	// create the real work thread
	for (idx = 0; idx < num; idx++)
	{
		ret = thread_create_detach(*pool, idx);
		if (0 != ret)
		{
			return -1;
		}
		(*pool)->num++;
	}

	return 0;
}


int thread_pool_add_worker(thread_pool_t *pool, void *(*process)(void *arg), void *arg)
{
	thread_worker_t *worker = NULL, *member = NULL;
	worker = (thread_worker_t*)calloc(1, sizeof(thread_worker_t));
	if (worker == NULL)
	{
		return -1;
	}

	worker->process = process;
	worker->arg = arg;
	worker->next = NULL;

	pthread_mutex_lock(&(pool->queue_lock));

	member = pool->head;
	if (member != NULL)
	{
		while(NULL != member->next) member = member->next;
		member->next = worker;
	}
	else
	{
		pool->head = worker;
	}

	pool->queue_size++;

	pthread_mutex_unlock(&(pool->queue_lock));
	pthread_cond_signal(&(pool->queue_ready));
}

int thread_pool_keepalive(thread_pool_t *pool)
{
	int idx = 0, ret = 0;

	for (idx = 0; idx < pool->num; idx++)
	{
		ret = pthread_kill(pool->threadid[idx], 0);
		if (ESRCH == ret)
		{
			ret = thread_create_detach(pool, idx);
			if (ret < 0)
			{
				return -1;
			}
		}
	}

	return 0;
}

int thread_pool_destroy(thread_pool_t *pool)
{
	int idx = 0, ret = 0;
	thread_worker_t *member = NULL;
	if (false != pool->isdestroy)
	{
		return -1;
	}

	pool->isdestroy = true;

	pthread_cond_broadcast(&(pool->queue_ready));
	for (idx = 0; idx < pool->num; idx++)
	{
		ret = pthread_kill(pool->threadid[idx], 0);
		if (ESRCH == ret)
		{
			continue;
		}
		else
		{
			idx--;
			sleep(1);
		}
	}

	free(pool->threadid);
	pool->threadid = NULL;

	while(NULL != pool->head)
	{
		member = pool->head;
		pool->head = member->next;
		free(member);
	}

	pthread_mutex_destroy(&(pool->queue_lock));
	pthread_cond_destroy(&(pool->queue_ready));
	free(pool);

	return 0;
}

static int thread_create_detach(thread_pool_t *pool, int idx)
{
	int ret = 0;
	pthread_attr_t attr;

	do
	{
		ret = pthread_attr_init(&attr);
		if (0 != ret)
		{
			return -1;
		}

		ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (0 != ret)
		{
			return -1;
		}

		ret = pthread_create(&((*pool).threadid[idx]), &attr, thread_routine, &pool);
		if (0 != ret)
		{
			pthread_attr_destroy(&attr);
			if (EINTR == errno)
			{
				continue;
			}

			return -1;
		}

		pthread_attr_destroy(&attr);
	}while(0);

	return 0;
}

static void *thread_routine(void *arg)
{
	thread_worker_t *worker = NULL;
	thread_pool_t *pool = (thread_pool_t*)arg;

	while(1)
	{
		pthread_mutex_lock(&(pool->queue_lock));
		while((false == pool->isdestroy) && (0 == pool->queue_size))
		{
			pthread_cond_wait(&(pool->queue_ready), &(pool->queue_lock));
		}

		if (false != pool->isdestroy)
		{
			pthread_mutex_unlock(&(pool->queue_lock));
			pthread_exit(NULL);
		}

		pool->queue_size--;
		worker = pool->head;
		pool->head = worker->next;
		pthread_mutex_unlock(&(pool->queue_lock));

		(*(worker->process))(worker->arg);

		free(worker);
		worker = NULL;
	}
}

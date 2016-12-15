/*
 * ClsABTbl.h
 *
 *  Created on: 2016年4月18日
 *      Author: zhangjl
 */

#ifndef CLSABTBL_H_
#define CLSABTBL_H_

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

typedef void*  ab_handle;
typedef void   (*callback_proc)(void*pData);

class ClsABTbl {
public:
	ClsABTbl();
	~ClsABTbl();

	ClsABTbl(int size_item, int capability, callback_proc proc_func);

	int writeAB(void *pData);
	int readAB(void);

private:
	pthread_mutex_t   m_lock;
	void              **pWList, **pRList;
	int               item_countW, item_countR;
	int               size_item;
	int               capability;
	int               ab_bytes;
	callback_proc     proc_func;

};
#endif /* CLSABTBL_H_ */


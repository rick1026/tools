/*
 * ClsABTbl.cpp
 *
 *  Created on: 2016年4月18日
 *      Author: zhangjl
 */
#include <strings.h>
#include "ClsABTbl.h"

ClsABTbl::ClsABTbl() {
	// TODO Auto-generated constructor stub
	printf("Please initialize the object using ClsABTbl(size_data, capability)\n");
	exit(1);
}

ClsABTbl::~ClsABTbl() {
	// TODO Auto-generated destructor stub
}

ClsABTbl::ClsABTbl(int size_item, int capability, callback_proc proc_func) {
	// TODO Auto-generated destructor stub
	this->size_item = size_item;
	this->capability = capability;
	this->ab_bytes = sizeof(void*) * capability; // the data saved in the ABTbl is the address of the
	                                             // real item, so the bytes of every A/B table is
	                                             // sizeof(void*)*capability, not size_item*capability

	//printf("sizeof(void*) = %d, size_item = %d, capability = %d, ab_bytes = %d\n", sizeof(void*), this->size_item, this->capability, ab_bytes);

	pWList = (void**)malloc(sizeof(void*) * capability);
	if (pWList == NULL)
	{
		printf("ClsABTbl Constructor: malloc pListA failed, exit!\n");
		exit(1);
	}
	pRList = (void**)malloc(sizeof(void*) * capability);
	if (pRList == NULL)
	{
		printf("ClsABTbl Constructor: malloc pListA failed, exit!\n");
		free(pWList);
		exit(1);
	}

	//printf("constructor: allocate memory success, addr of pWList = %p, addr of pRList = %p!\n", pWList, pRList);

	pthread_mutex_init(&m_lock, NULL);
	this->proc_func = proc_func;
	item_countW = item_countR = 0;
	bzero(pWList, ab_bytes);
	bzero(pRList, ab_bytes);

	//printf("constructor: item_countW = %d, item_countR = %d\n", item_countW, item_countR);
}

// the space to save the new item should be allocated by the caller.
int ClsABTbl::writeAB(void *pData)
{
	pthread_mutex_lock(&m_lock);
	if (item_countW < capability)
	{
		*(pWList + item_countW) = pData;

		//printf("ClsABTbl: writeAB success, pWList = %p, pWList + %d = %p, address = %p\n", pWList, item_countW, pWList + item_countW, *(pWList + item_countW));
		item_countW++;
	}
	pthread_mutex_unlock(&m_lock);

	return 0;
}

//
int ClsABTbl::readAB(void)
{
	pthread_mutex_lock(&m_lock);

	void **temp = pWList;           // save the address of writelist to temp variable
	int  temp_cnt = item_countW;    // save the item count to temp variable

	pWList = pRList;
	pRList = temp;                  // change the ReadList to current WriteList
	item_countR = temp_cnt;         // save the item count in the WriteList
	item_countW = 0;

	bzero(pWList, ab_bytes);

	//printf("readAB: exchange the write/read table, new pWList = %p, new pRList = %p\n", pWList, pRList);
	//printf("readAB: item_countR = %d\n", item_countR);

	pthread_mutex_unlock(&m_lock);

	int i = 0;
	for (i = 0; i< item_countR; i++)
	{
		//printf("readAB: read data, pRList = %p, pRList + %d = %p, data address = %p\n", pRList, i, pRList + i, *(pRList + i));
		this->proc_func(*(pRList + i));

		//printf("readAB: read data over, free addr = %p\n\n", *(pRList + i));
		*(pRList + i) = NULL; // The content must be free in the proc_func to avoid memory-leak
	}



	return 0;
}




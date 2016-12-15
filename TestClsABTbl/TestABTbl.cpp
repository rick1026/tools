/*
 * TestABTbl.cpp
 *
 *  Created on: 2016年4月18日
 *      Author: zhangjl
 */

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<pthread.h>

#include "ClsABTbl.h"

typedef struct person_info
{
	char name[32];
	int  age;
}stru_person;

void *thread_push_data(void*);
void *thread_pop_data(void*);
void display_data(void* ptr);
ClsABTbl *ab_data;

#define LOOP    {do{sleep(30)}while(1);}
int main(int argc, char **argv)
{
	pthread_t hdl_push_thread = NULL, hdl_pop_thread = NULL;
	ab_data = new ClsABTbl(sizeof(stru_person), 128, display_data);

	pthread_create(&hdl_push_thread, NULL, thread_push_data, NULL);
	pthread_create(&hdl_pop_thread, NULL, thread_pop_data, NULL);

	do{
		sleep(30);
	}while(1);

	return 0;
}

void *thread_push_data(void* arg)
{
	int count = 0;
	while(1)
	{
		sleep(1);

		stru_person *new_person = (stru_person*)calloc(1, sizeof(stru_person));
		snprintf(new_person->name, 31, "name%05d", count);
		new_person->age = count++;

		ab_data->writeAB(new_person);
		printf("writeData to ABTable, address of new node = %p\n", new_person);
	}

	return NULL;
}

void *thread_pop_data(void *arg)
{
	while(1)
	{
		sleep(10);
		ab_data->readAB();
	}

	return NULL;
}

void display_data(void* ptr)
{
	stru_person *obj = (stru_person*)ptr;
	printf("person_information, address = %p:\n", obj);
	printf("\tname = [%s]\n", obj->name);
	printf("\tage = %d\n", obj->age);

	free(ptr);
	return;
}






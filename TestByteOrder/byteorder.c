/*
 * byteorder.cpp
 *
 *  Created on: 2016年5月6日
 *      Author: zhangjl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "byteorder.h"

#define MY_LITTLE_ENDIAN        1
#define MY_BIG_ENDIAN           2
#define NET_ENDIAN           2

static inline int get_local_order()
{
	unsigned short temp = 0x0001;

	if (*(unsigned char*)(&temp) == 0x01)
		return MY_LITTLE_ENDIAN;
	else
		return MY_BIG_ENDIAN;
}
char htonl_nbytes(int n, unsigned char *content)
{
	static char local_byteorder = 0;

	// check the byteorder of local machine
	if (local_byteorder == 0)
	{
		local_byteorder = get_local_order();
	}

	// if the local byteorder is same as network byteorder, no need to convert
	if (local_byteorder == NET_ENDIAN)
		return 0;

	unsigned char *temp = (unsigned char*)malloc(n);
	bzero(temp, n);

	int i = 0, max = n - 1;
	for (i = 0; i < max; i++)
	{
		*(temp + i) = *(content + max - i);
	}

	memcpy(content, temp, n);
	free(temp);

	return 0;
}

char print_hex(int n, unsigned char *content, char *note)
{
	printf("%s\n", note);
	printf("-----------------------------------\n");
	int i = 0, j = 1;
	for (i = 0; i < n; i++, j++)
	{
		printf("%02X ", *((unsigned char*)content + i));

		if ((j % 8) == 0)
					printf(" ");

		if ((j % 16) == 0)
			printf("\n");
	}

	printf("\n");
	printf("-----------------------------------\n");

	return 0;

}

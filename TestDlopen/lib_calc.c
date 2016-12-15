/*
 * lib_calc.c
 *
 *  Created on: Dec 8, 2016
 *      Author: root
 */
#include <stdio.h>
#include "lib_calc.h"

void swap(int *x, int *y)
{
	printf("enter swap of dynamic library......\n");
	int temp = *x;
	*x = *y;
	*y = temp;
}


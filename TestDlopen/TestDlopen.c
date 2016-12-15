/*
 * TestDlopen.c
 *
 *  Created on: Dec 8, 2016
 *      Author: root
 */

#include<dlfcn.h>
#include<string.h>
#include<signal.h>
#include<unistd.h>

void (*fp_swap)(int*, int *);

int main(int argc, char **argv)
{
	void *dl_hdl = NULL;
	int x = 8, y = 10;
	dl_hdl = dlopen("./libcalc.so", RTLD_LAZY);
	fp_swap = dlsym(dl_hdl, "swap");

	printf("before swap: x = %d, y = %d\n", x, y);
	fp_swap(&x, &y);
	printf("after swap: x = %d, y = %d\n", x, y);

	dlclose(dl_hdl);
	return 0;
}


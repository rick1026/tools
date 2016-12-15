/*
 * main.cpp
 *
 *  Created on: 2016年5月6日
 *      Author: zhangjl
 */

#include "byteorder.h"

int main(int argc, char **argv)
{
	char string_print[] = "This is a program to test the function of convert byteorder!";

	print_hex(sizeof(string_print), (unsigned char*)string_print, "The content of string_print is:");

	printf("before convert: [%s]\n", string_print);

	htonl_nbytes(sizeof(string_print) - 1, string_print);

	printf("after convert: [%s]\n", string_print);
	return 0;
}


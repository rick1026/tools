/*
 * byteorder.h
 *
 *  Created on: 2016年5月6日
 *      Author: zhangjl
 */

#ifndef BYTEORDER_H_
#define BYTEORDER_H_

char htonl_nbytes(int n, unsigned char *content);
char print_hex(int n, unsigned char *content, char *note);

#endif /* BYTEORDER_H_ */

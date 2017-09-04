/*
 * TestStringSplit.cpp
 *
 *  Created on: 2016年6月13日
 *      Author: zhangjl
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int strsplit(char *string, int stringlen, char **tokens, int maxtokens, char delim);

int main(int argc, char **argv)
{
	char origin_string[] = "abcd:12345:ABCD:hh:jj:kk:mm:nn:pp:dd:rr:ss:gg:ff:xx:yy:zz";

	char *rslt[16];
	printf("string: [%s]\n", origin_string);
	int num = strsplit(origin_string, strlen(origin_string), rslt, 8, ':');

	int i = 0;
	for (i = 0; i < num; i++)
	{
		printf("rslt[%d] = %s\n", i, rslt[i]);
	}

	char origin_string2[] = ":1111:2222::4444:5555:";
	char *rslt2[8];
	printf("string2: [%s]\n", origin_string2);
	num = strsplit(origin_string2, strlen(origin_string2), rslt2, 8, ':');
	for (i = 0; i < num; i++)
	{
		printf("rslt2[%d] = %s\n", i, rslt2[i]);
	}

	return 0;
}

/*
 * strsplit  分割字符串
 * parameter: string     原始字符串
 *            stringlen  原始字符串长度
 *            tokens     指针数组，用来返回分割后字符串的地址
 *            maxtokens  指针数组德最大长度
 *            delim      用来分割的字符
 *  返回值:
 *      出错返回-1，正常返回分割字符串德个数
 *  注意:
 *      该分割方法会修改原始字符串
 */
int strsplit(char *string, int stringlen, char **tokens, int maxtokens, char delim)
{
	int i, tok = 0;
	int tokstart = 1; /* first token is right at start of string */

	if (string == NULL || tokens == NULL)
	{
		return -1;
	}

	for (i = 0; i < stringlen; i++)
	{
		if (string[i] == '\0' || tok >= maxtokens)
			break;

		if (tokstart)
		{
			tokstart = 0;
			tokens[tok++] = &string[i];
		}

		if (string[i] == delim)
		{
			string[i] = '\0';
			tokstart = 1;
		}

#if 1
		if (tokstart && (i == (stringlen - 1)))
		{
			tokens[tok++] = &string[i];
			string[i] = '\0';
		}
#endif
	}
	return tok;
}


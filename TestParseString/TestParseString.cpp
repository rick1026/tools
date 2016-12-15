
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<strings.h>

#include"string_fns.h"


void parser_str_sscanf(char *buf, int buf_len);
void parser_int_sscanf(char *buf, int buf_len);
void parser_split(char *buf, int buf_len);

int main(int argc, char **argv)
{
	char buf[256] = {0}, *pStr[16];

	bzero(buf, sizeof(buf));
	sprintf(buf, "abc%sdef%s%sghi", "\t", "\t", "\t");
	parser_str_sscanf(buf, strlen(buf));
	parser_split(buf, strlen(buf));


	bzero(buf, sizeof(buf));
	sprintf(buf, "123%s456%s%s789", "\t", "\t", "\t");
	parser_int_sscanf(buf, strlen(buf));
	parser_split(buf, strlen(buf));



	return 0;
}

void parser_str_sscanf(char *buf, int buf_len)
{
	char str1[32], str2[32], str3[32], str4[32];
	bzero(str1, sizeof(str1));
	bzero(str2, sizeof(str2));
	bzero(str3, sizeof(str3));
	bzero(str4, sizeof(str4));

	sscanf(buf, "%s\t%s\t%s\t%s", str1, str2, str3, str4);

	printf("============= result of sscanf_parser string[%s]\n", buf);
	printf("str1[1] = %s\n", str1);
	printf("str1[2] = %s\n", str2);
	printf("str1[3] = %s\n", str3);
	printf("str1[4] = %s\n", str4);
	printf("=============\n\n");
}

void parser_int_sscanf(char *buf, int buf_len)
{
	int a = 0, b = 0, c = 0, d = 0;
	sscanf(buf, "%d\t%d\t%d\t%d", &a, &b, &c, &d);

	printf("============= result of sscanf_parser string[%s]\n", buf);
	printf("a = %d\n", a);
	printf("b = %d\n", b);
	printf("c = %d\n", c);
	printf("d = %d\n", d);
	printf("=============\n\n");
}

void parser_split(char *buf, int buf_len)
{
	char *pstr[4];
	int para_num = strsplit(buf, strlen(buf), pstr, 4, '\t');

	printf("============= result of split_parser string[%s]\n", buf);
	printf("para_num = %d\n", para_num);
	
	int i = 0;
	for(i = 0; i < para_num; i++)
	{
		printf("pstr[%d] = %s\n", i, pstr[i]);
	}
	printf("=============\n\n");
}

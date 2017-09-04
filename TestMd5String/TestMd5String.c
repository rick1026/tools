/*************************************************************************
	> File Name: TestMd5String.c
	> Author: ma6174
	> Mail: ma6174@163.com 
	> Created Time: Thu 24 Aug 2017 02:01:07 PM CST
 ************************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<strings.h>
#include<unistd.h>
#include<openssl/md5.h>

#define MAX_BUF_LEN  256
#define MINI_BUF_LEN 64
#define MD5_LONG unsigned int
#define MD5_CBLOCK	64
#define MD5_LBLOCK	(MD5_CBLOCK/4)
#define O_RDONLY	     00

#if 0
typedef struct MD5state_st {
	MD5_LONG A, B, C, D;
	MD5_LONG Nl, Nh;
	MD5_LONG data[MD5_LBLOCK];
	int num;
} MD5_CTX;
#endif

// echo -n "123" | md5sum
int  getStrMd5(char *str_src, char *str_md5);
int getMd5(const char *file, char *md5value);

int main(int argc, char **argv)
{
	MD5_CTX ctx;
	unsigned  char  *data= "123";
	unsigned  char  md[16];

	char  buf[33]={ '\0' };
	char  tmp[3]={ '\0' };
	int  i;

	MD5_Init(&ctx);
	MD5_Update(&ctx, data, strlen (data));
	MD5_Final(md, &ctx);
	for ( i=0; i<16; i++ ){
		sprintf (tmp, "%02X" ,md[i]);
		strcat (buf,tmp);
	}

	printf ( "%s\n" ,buf);
	return  0;
}

int getMd5(const char *file, char *md5value)
{
	int fd;
		char buf[MAX_BUF_LEN] = { };
		MD5_CTX ct;
		int len;
		int index;
		unsigned char final[16] = { };

		if (NULL != md5value)
		{
			if (NULL != file)
			{
				fd = open(file, O_RDONLY);
				if (-1 != fd)
				{
					bzero(&ct, sizeof(MD5_CTX));
					MD5_Init(&ct);
					while (0 < (len = read(fd, buf, MAX_BUF_LEN)))
					{
						MD5_Update(&ct, buf, len);
						bzero(buf, MAX_BUF_LEN);
					}
					MD5_Final(final, &ct);
					close(fd);
					for (len = 0, index = 0; len < 16; len++, index += 2)
					{
						snprintf(md5value + index, MINI_BUF_LEN - index, "%x",
								final[len] >> 4);

						snprintf(md5value + index + 1, MINI_BUF_LEN - index - 1,
								"%x", final[len] & 0x0f);
					}
					//printf("\n文件%s的md5值为 ->%s\n", file, md5value);
					return 0;
				}
			}
		}

		return -1;
}

int  getStrMd5(char *str_src, char *str_md5)
{
	int  i;  
	char  tmp[3]={'\0'};
	unsigned  char  md[16];
	bzero(md, sizeof(md));
	
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, str_src, strlen (str_src));
	MD5_Final(md, &ctx);

	for ( i=0; i < 16; i++ )
	{
		sprintf (tmp, "%02X" ,md[i]);
		strcat (str_md5,tmp);
	}   
										
	//printf ( "%s\n" ,str_md5);
	return 0;
}

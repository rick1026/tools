#include "string_fns.h"

/*
strsplit 分割字符串
参数:string  原始字符串
	 stringlen 原始字符串长度
	 tokens  指针数组，用来返回分割后字符串的地址
	 maxtokens 指针数组的最大长度
	 delim   用来分割的字符
返回值:
	 出错返回-1， 正常返回分割字符串的个数
注意:
     该分割方法会修改原始字符串
*/
int strsplit(char *string, int stringlen,
	     char **tokens, int maxtokens, char delim)
{
	int i, tok = 0;
	int tokstart = 1; /* first token is right at start of string */

	if (string == NULL || tokens == NULL)
		return -1;

	for (i = 0; i < stringlen; i++) {

		if (string[i] == '\0' || tok >= maxtokens)
			break;

		if (tokstart) {
			tokstart = 0;
			tokens[tok++] = &string[i];
		}
		if (string[i] == delim) {
			string[i] = '\0';
			tokstart = 1;
		}
	}
	return tok;
}

unsigned int parstr(const char *str, \
        char *result, \
        const char *delim, \
        const unsigned int num, \
        const unsigned int size)
{
  char  *pStr1, *pStr2, *pStr3;
  int   len, i = 0;

  len = strlen(str);

  pStr3 = pStr1 = (char*)malloc(len + 1);
  strncpy(pStr1, str, len + 1);
  pStr2 = strtok_r(pStr1, delim, &pStr1);

  while (pStr2 != 0 && i < num){
    strncpy((char *)(result + i * size), pStr2, size);
    pStr2 = strtok_r(NULL, delim, &pStr1);
    i ++;
  }

  free(pStr3);
  return i;
}



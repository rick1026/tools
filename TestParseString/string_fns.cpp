#include "string_fns.h"

/*
strsplit �ָ��ַ���
����:string  ԭʼ�ַ���
	 stringlen ԭʼ�ַ�������
	 tokens  ָ�����飬�������طָ���ַ����ĵ�ַ
	 maxtokens ָ���������󳤶�
	 delim   �����ָ���ַ�
����ֵ:
	 ������-1�� �������طָ��ַ����ĸ���
ע��:
     �÷ָ�����޸�ԭʼ�ַ���
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



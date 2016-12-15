#ifndef __STRING_FNS_H__
#define __STRING_FNS_H__
#include <string.h>
#include <stdlib.h>

int strsplit(char *string, int stringlen, char **tokens, int maxtokens, char delim);

unsigned int parstr(const char *str, \
        char *result, \
        const char *delim, \
        const unsigned int num, \
        const unsigned int size);

#endif

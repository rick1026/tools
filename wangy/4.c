#include <stdio.h>
#include <string.h>

int main(void)
{
	char row[128];
	char url[128];
	char host[128];
	char *p = NULL,q = NULL,m = NULL,k = NULL;
	bzero(row,sizeof(row));
	FILE *fp = fopen("./URL_rule.txt","r");
	FILE *pu = fopen("./url.txt","w+");
	FILE *ph = fopen("./host.txt","w+");
	while(fgets(row,128,fp) != NULL)
	{
		p = strstr(row,"com.cn");
		m = strstr(row,"net");
		n = strstr(row,"org");
		if(p == NULL)
		{
			q = strstr(row,"com");
			if(q == NULL)
			{
				k = strstr(row,"cn");
			}
		}
		p += 6;
		fwrite(row,p - row,1,fu);
		fputc('\n',fu);
		fprintf(fh,"%s\n",p);
	}
}

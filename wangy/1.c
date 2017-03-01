#include <string.h>
#include <stdio.h>
 #include <netinet/in.h>
unsigned long StrToIp(char *str)
{
        return ntohl(inet_addr(str));
}
int main(void)
{
	char row[128];
	unsigned int ip = 0;
	FILE *fp = fopen("./DIP_rule.txt","r");
	FILE *fw = fopen("./dip.txt","w+");
	bzero(row,sizeof(row));
	while(fgets(row,128,fp) != NULL)
	{
		ip = StrToIp(row);
		fprintf(fw,"%u\n",ip);
		bzero(row,sizeof(row));
	}
	fclose(fp);
	fclose(fw);

return 0;
}

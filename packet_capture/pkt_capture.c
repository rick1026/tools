/***************************************************************************
 *   Copyright (C) 2005 by hg                                              *
 *   brianhe@bupt.edu.cn                                                   *
 *                                                                         *
 *   Project name : BEAP                                                   *
 *   Program Name : beap_app_stat                                          *
 *   Version Number: 1.0                                                   *
 *   Base Version:   3.4.7.0
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/vfs.h>
#include <stdarg.h>

#include "pkt_capture_execute.h"
#include "pkt_capture_extern.h"

#define DEFAULT_SNAPLEN     1600
#define PCAP_TIMEOUT        5000
#define PACKETS_TO_WAIT     -1

#define EXIT_PROCESS() {exit(0);}

static unsigned char initPcap4Stat(void);
static char init_offline_file(char *cap_file_name);
static void pcap_mainloop(void);
static void mainLoop_file(char *file_name);
void mainDisp(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
static void MainLoop(void);
pcap_t *pcapHandle;

int main(int argc, char **argv)
{
	if (argc == 2) // read packet from capture file
	{
		init_offline_file(argv[1]);
	}
	else
	{
		MainLoop();
	}

	EXIT_PROCESS();
	return 1;
}

static char init_offline_file(char *cap_file_name)
{
	mainLoop_file(cap_file_name);
}

char xtoa(const unsigned char val, char *str)
{
	sprintf(str, "%02X", val);
	return 1;
}

char * mac2str(char *str, const unsigned char *mac)
{
	int i;
	char s[8];

	if (mac == NULL) return str;

	str[0] = 0;
	for (i = 0; i < 5; i++)
	{
		xtoa(mac[i], s);
		strcat(str, s);
		strcat(str, ":");
	}
	xtoa(mac[5], s);
	strcat(str, s);
	return str;
}

static unsigned char initPcap4Stat(void)
{
	struct bpf_program fcode;
	char ebuf[PCAP_ERRBUF_SIZE]; // pcap, capture packets
	pcapHandle = pcap_open_live("br-lan", DEFAULT_SNAPLEN, 1, PCAP_TIMEOUT, ebuf);
	if ((long) pcapHandle == -1)
	{
		perror("pcap_open_live error\n");
		return BEAP_FAIL;
	}
	else
	{
		printf("\n pcap_open_live success\n");
	}
	/*编译抓包FILTER*/
	if (pcap_compile(pcapHandle, &fcode, NULL, 1, 0) == -1)
	{
		printf("pcap_compile == -1\n");
		return BEAP_FAIL;
	}
	/*指定过滤FILTER*/
	if (pcap_setfilter(pcapHandle, &fcode) == -1)
	{
		printf("pcap_setfillter == -1\n");
		return BEAP_FAIL;
	}
	//
	pcap_open_done: return BEAP_SUCCESS;

}

static void MainLoop(void)
{
	pcap_mainloop();
}

static void pcap_mainloop(void)
{
	if (initPcap4Stat() == BEAP_FAIL)
	{
		printf("initPcap4Stat FAILED! will EXIT!\n");
		return;
	}
	pcap_loop(pcapHandle, PACKETS_TO_WAIT, mainDisp, NULL);
}
static void mainLoop_file(char *file_name)
{
	char errBuf[PCAP_ERRBUF_SIZE];
	printf("init_pcap_handle, load packets from file [%s]\n", file_name);
	pcap_t *pcap_open_hdl = pcap_open_offline(file_name, errBuf);
	if (pcap_open_hdl == NULL)
	{
		perror("pcap_open_offline error, exit!");
		return;
	}

	while (1)
	{
		pcap_dispatch(pcap_open_hdl, -1, mainDisp, file_name);
	}
}

int write_packet_to_file(char *file_name, char*data, int cap_len, int data_len)
{
	typedef struct __file_header
	{
		unsigned int iMagic;
		unsigned short iMaVersion;
		unsigned short iMiVersion;
		unsigned int iTimezone;
		unsigned int iSigFlags;
		unsigned int iSnapLen;
		unsigned int iLinkType;
	} file_header;

	typedef struct __pkthdr
	{
		unsigned int iTimeSecond;
		unsigned int iTimeSS;
		unsigned int iPLength;
		unsigned int iLength;
	} pkthdr;
	FILE *fp = fopen(file_name, "a+");
	struct stat f_stat;
	file_header fileHdr;
	unsigned char buf[128];
	memset(buf, 0, sizeof(buf));
	pkthdr packHdr;
	stat(file_name, &f_stat);
	if (f_stat.st_size == 0)
	{
		memset(&fileHdr, 0, sizeof(fileHdr));
		fileHdr.iMagic = 0xa1b2c3d4;
		fileHdr.iMaVersion = 0x2;
		fileHdr.iMiVersion = 0x4;
		fileHdr.iTimezone = 0x0;
		fileHdr.iSigFlags = 0x0;
		fileHdr.iSnapLen = 0xffff;
		fileHdr.iLinkType = 0x1;
		fwrite(&fileHdr, sizeof(fileHdr), 1, fp);
	}
	memset(&packHdr, 0, sizeof(packHdr));
	packHdr.iTimeSecond = time(NULL);
	packHdr.iTimeSS = 0;
	packHdr.iPLength = cap_len;
	packHdr.iLength = data_len;
	fwrite(&packHdr, sizeof(packHdr), 1, fp);
	fwrite(data, 1, data_len, fp);
	fclose(fp);
}

void mainDisp(unsigned char *pClient, const struct pcap_pkthdr *pHead, const unsigned char *pPacket)
{
	//write_packet_to_file("./debug.cap",(char *)pPacket, pHead->caplen, pHead->caplen);

	pkt_exec_receiver(pHead, (void *) pPacket, pHead->caplen, pHead->ts);

}


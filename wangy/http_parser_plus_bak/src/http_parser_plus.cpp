/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <cstdlib>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_include.h"
#include "main_process.h"

using namespace std;

static struct list_head     list_capture_intf;
static char                 cap_file_name[256];

static char                 flag_intf = 0, flag_file = 0;
static char                 errBuf[PCAP_ERRBUF_SIZE];
static char                 pcap_filter[128] = "tcp and port 80";
static pcap_t               *pcap_open_handle[32];
static struct pollfd        poll_pcap_fd[32];

cls_pkt_processor           *processor;

void packet_processer(unsigned char *arg, const struct pcap_pkthdr *ph, const unsigned char *packet);

int main(int argc, char *argv[])
{
	processor = new cls_pkt_processor(0);

  static struct list_head     list_capture_intf;
  static char                 errBuf[PCAP_ERRBUF_SIZE];
  static pcap_t               *pcap_open_handle[32];
  static pcap_dumper_t        *pcap_dump_fd;
  static struct pollfd        poll_pcap_fd[32];
  static char                 pcap_filter[128] = "tcp and port 80";

  void print_list_interf(struct list_head *list_head);
  char init_pcap_handle(struct list_head *list_head);

  struct option long_options[] =
    {
      {"set-interface", required_argument, NULL, 'i'},
      {"set-file", required_argument, NULL, 'f'},
      {0, 0, 0, 0}
    };
  char *optstring = (char*)"i:f:";


  int opt, digit_optind = 0, option_index = 0;
  char flag_getopt_long = 0;

  INIT_LIST_HEAD(&list_capture_intf);

  while((opt = getopt_long(argc, argv, optstring, long_options, &option_index)) != -1)
  {
    flag_getopt_long = 1;

    switch(opt)
    {
    case '?':
      printf("Invalid option[%s], please usage: \'%s -i intfname or -f filename\'\n", argv[optind - 1], argv[0]);
      return 1;
      break;
    case 'i':
      if (flag_file)
      {
        printf("ERROR, 111 you cann't specify both interface and file meanwhile\n");
        return 1;
      }
      else
      {
        // you can specify more than one interface which will be captured on
        // add the specified interface to the tail of the link_list
        flag_intf++ ;
        struCapIntf *intf = (struCapIntf*)malloc(sizeof(struCapIntf));
        strncpy(intf->intf_name, optarg, 15);
        list_add_tail(&(intf->ptr), &list_capture_intf);
      }
      break;
    case 'f':
      if (flag_intf)
      {
        printf("ERROR, 222 you cann't specify both interface and file meanwhile\n");
        return 1;
      }
      // you can specify only one capture-file to load packets
      else if (flag_file)
      {
        printf("ERROR, you cann't specify more than one capture-file\n");
        return 1;
      }
      else
      {
        flag_file++;
        bzero(cap_file_name, sizeof(cap_file_name));
        strncpy(cap_file_name, optarg, sizeof(cap_file_name) - 1);
        strncpy(cap_file_name, argv[2], sizeof(cap_file_name) - 1);
        printf("00000000000000000000, flag_file = %d, argv[2] = %s, cap_file_name = %s\n", flag_file, argv[2], cap_file_name);
        
      }
      break;
    default:
      break;
    }
  }


  if (flag_getopt_long == 0)
  {
    printf("Invalid option[%s], please usage: \'%s -i intfname or -f filename\'\n", argv[optind - 1], argv[0], argv[0]);
    exit(1);
  }

  print_list_interf(&list_capture_intf);

  /** step-3, initlize some resources needed for ressemble */
  //InitHttpParserPlugin();
  //tcp_reassemble_init();
  //init_conn_hash_cache();
  //init_http_cache();

  /** step-3, register pcap to capture packets from interface or specified file */
  char ret = init_pcap_handle(&list_capture_intf);

  while(1)
    sleep(30);

  return EXIT_SUCCESS;
}


void print_list_interf(struct list_head *list_head)
{
  struct list_head *p = NULL;
  struCapIntf *entry = NULL;

  printf("There are %d interfaces need to be captured on!!!\n", flag_intf);
  list_for_each(p, list_head)
  {
    entry = list_entry(p, struCapIntf, ptr);
    printf("address of entry: %08X\n", (void*)entry);
    printf("interface_name = %s\n", entry->intf_name);
  }
}

char init_pcap_handle(struct list_head *list_cap_intf)
{
    printf("init_pcap_handle..........\n");
  if (flag_intf)
  {
    printf("init_pcap_handle, capture packets on interfaces\n");
    struct list_head *p = NULL;
    struCapIntf *entry = NULL;
    int i = 0;

    list_for_each(p, list_cap_intf)
    {
      entry = list_entry(p, struCapIntf, ptr);

      printf("interface_name = %s\n", entry->intf_name);
      //pcap_t *pcap_open_hdl = pcap_open_live(entry->intf_name, 65535, 1, 5000, errBuf);
      pcap_t *pcap_open_hdl = pcap_open_live("em4", 65535, 1, 5000, errBuf);

      if ((long)pcap_open_hdl == -1)
      {
        perror("pcap_open_live eror, exit!");
        exit(1);
      }

      struct bpf_program filter;
      pcap_compile(pcap_open_hdl, &filter, pcap_filter, 1, 0);
      pcap_setfilter(pcap_open_hdl, &filter);
      pcap_open_handle[i] = pcap_open_hdl;
      poll_pcap_fd[i].fd = pcap_get_selectable_fd(pcap_open_hdl);
      poll_pcap_fd[i].events = POLLIN;

      i++;
    }

    int cap_intf_num = flag_intf;
    while(1)
    {
      //pcap_dispatch(pcap_open_hdl, 1, packet_processer, interf_name);
      int ret = poll(poll_pcap_fd, cap_intf_num, 2000);
      if (ret > 0)
      {
        int i = 0;
        struct list_head *p = NULL;
        struCapIntf *entry = NULL;

        //list_for_each(p, &list_capture_intf)
        {
          entry = list_entry(p, struCapIntf, ptr);
          if ((poll_pcap_fd[i].revents & POLLIN) != 0)
            //pcap_dispatch(pcap_open_handle[i], 1, packet_processer, (unsigned char*)entry->intf_name);
            pcap_dispatch(pcap_open_handle[i], 1, packet_processer, (unsigned char*)("em4"));
          i++;
        }
      }
    }
  }
  else if (flag_file)
  {
    printf("init_pcap_handle, load packets from file flag_file = %d, [%s]\n", flag_file, cap_file_name);
    pcap_t *pcap_open_hdl = pcap_open_offline(cap_file_name, errBuf);
    if (pcap_open_hdl == NULL)
    {
      perror("pcap_open_offline error, exit!");
      exit(1);
    }

    while(1)
    {
        pcap_dispatch(pcap_open_hdl, 1, packet_processer, (unsigned char*)cap_file_name);
    }
  }
  else
  {
      printf("parameter error!\n");
  }

  printf("1111111111\n");

  while(1)
  {
      sleep(300);
  }

  return 0;
}

void packet_processer(unsigned char *arg, const struct pcap_pkthdr *ph, const unsigned char *packet)
{
    
    processor->packet_processer(arg, ph, packet);
}

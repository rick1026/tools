/***************************************************************************
 *   Copyright (C) 2015 by root                                            *
 *   root@localhost.localdomain                                            *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pkt_processor.h"
//#define __PRINT_LOG

#define MEMCPY_1BYTE(p,value,len) do{*(p) = (value);p += 1;}while(0);
#define MEMCPY_2BYTE(p,value,len) do{unsigned short sTemp = htons(value); *((unsigned short *)(p)) = sTemp;(p)+= 2;}while(0);
#define MEMCPY_4BYTE(p,value,len) do{unsigned int iTemp = htonl(value); *((unsigned int *)(p)) = iTemp;(p)+=4;}while(0);
#define MEMCPY_STR(p,value,len) do{ memcpy((p),(value),len);(p) += (len);}while(0);
#define MEMCPY_STRUCT(p,value,len) do{ memcpy((p),&(value),len);(p) += (len);}while(0);



#if 1
char *
ip2str (unsigned int ip, char *str)
{
  struct in_addr addr;
  addr.s_addr = htonl (ip);
  strcpy (str, inet_ntoa (addr));
  return str;
}
#endif

unsigned int
conn_hash_func (void *key)
{
  unsigned int i = 0, ret = 0;
#if 0
// modified on 20150807
  for (i = 0; i < sizeof (TCPsessionID); i++)
    {
//printf("%02x\n", *((unsigned char*)key + i));
      ret += *((unsigned char *) ((unsigned char *) key + i));
    }
//printf("ret = %u\n", ret);
#endif

  for (i = 0; i < sizeof (TCPsessionID); i += 2)
    {
      ret += *(unsigned short *) (key + i);
    }

  return ret & MAX_INDEX_CONN_HASH;
}

unsigned char
conn_comp_func (void *key1, void *key2)
{
  TCPsessionID *tcp_id1, *tcp_id2;
  if (!memcmp (key1, key2, sizeof (TCPsessionID)))
    return 0;

  tcp_id1 = (TCPsessionID *) key1;
  tcp_id2 = (TCPsessionID *) key2;
  if (tcp_id1->src_ip == tcp_id2->dst_ip &&
      tcp_id1->dst_ip == tcp_id2->src_ip &&
      tcp_id1->src_port == tcp_id2->dst_port &&
      tcp_id1->dst_port == tcp_id2->src_port)
    return 0;

  return 1;
}

inline void
cls_pkt_processor::clear_conn_hash ()
{
  time_t cur_time = time(NULL);
  stru_hash_node *p_conn = NULL;
  hash_bucket *pPrevBucket = NULL, *pBucket = NULL;
 sem_wait(&conn_hash_sem);
  for (int i = 0; i < SIZE_CACHE_CONN_HASH; i++)
    {
      if ((pPrevBucket = conn_hash->hashtable[i]) == NULL)
	continue;
      pBucket = pPrevBucket->ptr.next_hash;
      while (pPrevBucket)
	{
	  p_conn = (stru_hash_node *) (pPrevBucket->content);
	  if(cur_time - p_conn->time_stamp > 3)
	    {
	      if (p_conn->conn_node)
		{
		  free (p_conn->conn_node);
		  p_conn->conn_node = NULL;
		}
	      if (p_conn->tcp_node)
		{
		  free (p_conn->tcp_node);
		  p_conn->tcp_node= NULL;
		}
	      if (p_conn->http_node)
		{
    	 ClsHTTPReassemble.free_list(&(p_conn->http_node->sdu_list_up));
   		 ClsHTTPReassemble.free_list(&(p_conn->http_node->sdu_list_down));
		  free (p_conn->http_node);
		  p_conn->http_node= NULL;
		}

		  remove_hash(conn_hash,pPrevBucket);
	      free (pPrevBucket->content);
		  pPrevBucket->content = NULL;
	      free (pPrevBucket);
	      pPrevBucket = NULL;
	    }
	  pPrevBucket = pBucket;
	  pBucket = (pBucket == NULL) ? NULL : pBucket->ptr.next_hash;
	}
    }
sem_post(&conn_hash_sem);
}

cls_pkt_processor::cls_pkt_processor ()
{
  //Initialize();
}

cls_pkt_processor::cls_pkt_processor (int client_id)
{
  this->client_id = client_id;

  Initialize ();
}

cls_pkt_processor::~cls_pkt_processor ()
{
}

char
cls_pkt_processor::read_house_info ()
{
}

char
cls_pkt_processor::read_comm_conf_from_file ()
{
  char row[256];
  FILE *fd = fopen ("/var/beap_conf/IDC_port_conf.txt", "r");
  if (fd == NULL)
    {
      printf
	("read_comm_conf: open file /var/beap_conf/IDC_port_conf.txt error!\n");
      serv_port_policy_update = 61001 + client_id;
      client_port_ud_log = 61000;
      client_port_ud_attach = 61100;
      return 0;
    }

  bzero (row, sizeof (row));
  while (fgets (row, sizeof (row), fd) != NULL)
    {
      if (row[0] == '\n' || row[0] == '#')
	continue;

      row[strlen (row) - 1] = '\0';

      char *pos = NULL;
      if ((pos = strstr (row, "<PORT_LISTEN_UD_LOG>")) != NULL)
	{
	  client_port_ud_log = atoi (pos + strlen ("<PORT_LISTEN_UD_LOG>"));
	}
      else if ((pos = strstr (row, "<PORT_LISTEN_ATTATCH>")) != NULL)
	{
	  client_port_ud_attach =
	    atoi (pos + strlen ("<PORT_LISTEN_ATTATCH>"));
	}
      else if ((pos = strstr (row, "<PORT_POLICY_UPDATE_BEGIN>")) != NULL)
	{
	  serv_port_policy_update =
	    atoi (pos + strlen ("<PORT_POLICY_UPDATE_BEGIN>")) + client_id;
	}
      else
	continue;
    }

  fclose (fd);
  return 0;
}

char
cls_pkt_processor::load_ISMS_policies ()
{
  if (mwm_handle != NULL)
    {
      mwmFree (mwm_handle);
      mwm_handle == NULL;
    }
  mwm_handle = mwmNew ();
  if (mwm_handle == NULL)
    {
      printf ("load_ISMS_policies: mwm_handle == NULL, exit!!!!!\n");
      exit (1);
    }
  else
    {
      printf ("load_ISMS_policies: mwm_handle == mwmNew() success!!!!!\n");
    }

  map_site_rule.clear ();
  map_url_rule.clear ();
  map_proto_rule.clear ();
  map_sip_rule.clear ();
  map_dip_rule.clear ();
  map_sport_rule.clear ();
  map_dport_rule.clear ();

  ClsDBOperation.get_ISMS_policy (house_id, vector_policy);
  size_t len = vector_policy.size ();

  stru_ISMS_policy temp_policy;
  char keyword[256];
  char keyword_gbk[512];
  char keyword_big5[512];

  printf ("\n\n*******************************************************\n",
	  len);
  printf ("There are %d ISMS policies totally\n", len);
  char mwm_add_flag = 0;
  int keyword_ply_num = 0;
  int keyword_num_temp = 0;

  for (size_t i = 0; i < len; i++)
    {
      //printf("---------------------------------------------------------\n");
      temp_policy = vector_policy[i];
      /*
         printf("ISMS_policy[%d].MsgNo: %lu\n", i, temp_policy.MsgNo);
         printf("ISMS_policy[%d].CmdID: %s\n", i, temp_policy.CmdID);
         printf("ISMS_policy[%d].Type: %d\n", i, temp_policy.Type);
         printf("ISMS_policy[%d].RuleNum: %d\n", i, temp_policy.RuleNum);
         printf("ISMS_policy[%d].BlockFlag: %d\n", i, temp_policy.BlockFlag);
         printf("ISMS_policy[%d].LogFlag: %d\n", i, temp_policy.LogFlag);
         printf("ISMS_policy[%d].Level: %d\n", i, temp_policy.Level);
         printf("ISMS_policy[%d].EffectTime: %lu\n", i, temp_policy.EffectTime);
         printf("ISMS_policy[%d].ExpireTime: %lu\n", i, temp_policy.ExpireTime);
         printf("ISMS_policy[%d].MsgSerialNo: %lu\n", i, temp_policy.MsgSerialNo);
         printf("ISMS_policy[%d].BindStatus: %d\n", i, temp_policy.BindStatus);
         printf("ISMS_policy[%d].BindHouseID: %s\n", i, temp_policy.BindHouseID);
         printf("ISMS_policy[%d].UpdateTime: %lu\n", i, temp_policy.UpdateTime);
         printf("ISMS_policy[%d].rule_info:\n");
       */

      size_t len_rule = temp_policy.vector_rule.size ();
      struct stru_ISMS_policy_rule temp_rule;
      for (size_t j = 0; j < len_rule; j++)
	{
	  int nocase = 1;
	  stru_prule_position coordinate = { i, j };
	  temp_rule = temp_policy.vector_rule[j];
	  vector_policy[i].BMap.setbit (j);
	  //printf("\trule[%d].policy_index: %d\n", j, temp_rule.policy_index);
	  //printf("\trule[%d].Rule_SubType: %d\n", j, temp_rule.Rule_SubType);
	  switch (temp_rule.Rule_SubType)
	    {
	    case 1:		// host rule
	      //printf("\trule[%d].Rule_Host: %s, domain rule\n", j, temp_rule.Rule_Host);
	      break;
	    case 2:
	      //printf("\trule[%d].Rule_Url: %s, URL rule\n", j, temp_rule.Rule_Url);
	      break;
	    case 3:
	      //printf("\trule[%d].Rule_Keyword: range = %d, %s, Keyword rule\n", j, temp_rule.Rule_KeyRange, temp_rule.Rule_Keyword);


	      bzero (keyword, sizeof (keyword));
	      bzero (keyword_gbk, sizeof (keyword_gbk));
	      bzero (keyword_big5, sizeof (keyword_big5));
	      memcpy (keyword, temp_rule.Rule_Keyword, sizeof (keyword));
	      //sprintf (keyword, "keyword%05d", ++keyword_num_temp);
//printf("keyword = %s,len = %d\n",temp_rule.Rule_Keyword,strlen((const char *)(temp_rule.Rule_Keyword)));
	      if (vector_policy[i].keyword_first == NULL)
		{
		  vector_policy[i].keyword_first =
		    (char *) calloc (strlen (keyword) + 1, 1);
		  memcpy (vector_policy[i].keyword_first, keyword,
			  strlen (keyword));
		}
	      stru_result_info info;
	      info.rule_id = i;
	      info.key_id = j;
	      bzero (info.keyword, sizeof (info.keyword));
	      strcpy (info.keyword, keyword);
	      result_info_list.push_back (info);
	      /*
	         printf("keyword: addr = %p, len = %d, content = <%s>\n", keyword, strlen(keyword), keyword);
	         printf("keyword_gbk: addr = %p, len = %d, content = <%s>\n", keyword_gbk, strlen(keyword_gbk), keyword_gbk);
	         printf("keyword_big5: addr = %p, len = %d, content = <%s>\n", keyword_big5, strlen(keyword_big5), keyword_big5);
	       */

	      iconv_utf8_gbk (keyword_gbk, sizeof (keyword_gbk), keyword,
			      strlen (keyword));
	      //iconv_utf8_Big5(keyword_big5, sizeof(keyword_big5), keyword, strlen(keyword));

	      /*
	         printf("keyword: addr = %p, len = %d, content = <%s>\n",keyword, strlen(keyword), keyword);
	         printf("keyword_gbk: addr = %p, len = %d, content = <%s>\n",keyword_gbk, strlen(keyword_gbk), keyword_gbk);
	         printf("keyword_big5: addr = %p, len = %d, content = <%s>\n",keyword_big5, strlen(keyword_big5), keyword_big5);
	       */

	      //if (result_info_list.size() > 1024)
	      //      break;


	      mwmAddPatternEx (mwm_handle,
			       (unsigned char *) (keyword),
			       strlen (keyword), nocase, 0, 0,
			       result_info_list.size () - 1, 0, 0);

	      /*
	         mwmAddPatternEx (mwm_handle,
	         (unsigned char *) (keyword_gbk),
	         strlen (keyword_gbk), nocase, 0, 0, result_info_list.size()-1, 0, 0);
	         mwmAddPatternEx(mwm_handle,
	         (unsigned char*)(keyword_big5),
	         strlen(keyword_big5),
	         nocase,
	         0,
	         0,
	         result_info_list.size()-1,
	         0,
	         0);
	       */
	      mwm_add_flag = 1;
	      //if (result_info_list.size () >= 1024)
	      //      goto load_end;
	      break;
	    case 4:
	      /*
	         printf("\trule[%d].Rule_SIP, start = %lu, end = %lu, SIP rule\n",
	         j, temp_rule.Rule_SipStart, temp_rule.Rule_SipEnd);
	       */
	      break;
	    case 5:
	      /*
	         printf("\trule[%d].Rule_DIP, start = %lu, end = %lu, DIP rule\n",
	         j, temp_rule.Rule_DipStart, temp_rule.Rule_DipEnd);
	       */
	      break;
	    case 6:
	      /*
	         printf("\trule[%d].Rule_Sport, start = %d, end = %d, Sport rule\n",
	         j, temp_rule.Rule_SportStart, temp_rule.Rule_SportEnd);
	       */
	      break;
	    case 7:
	      /*
	         printf("\trule[%d].Rule_Dport, start = %d, end = %d, Dport rule\n",
	         j, temp_rule.Rule_DportStart, temp_rule.Rule_DportEnd);
	       */
	      break;
	    case 8:
	      //printf("\trule[%d].Rule_ProtoL4: %d, Proto rule\n", j, temp_rule.Rule_ProtoL4);
	      break;
	    default:
	      break;
	    }

	  add_rule_to_map (coordinate, temp_rule);
	}
      //printf("ISMS_policy[%d].BMap: %s\n", i, vector_policy[i].BMap.getmap().c_str());
      //printf("---------------------------------------------------------\n");

    }
load_end:
  if (mwm_add_flag)
    mwmPrepPatterns (mwm_handle);
  printf ("*******************************************************\n", len);

  printf (">>>>>>>>>> The site rule information is as follows:\n");
  for (MapHostRuleInfo::iterator it = map_site_rule.begin ();
       it != map_site_rule.end (); it++)
    {
      printf ("host = <%s>\n", it->first.c_str ());
      ListRuleInfo & rule_list = it->second;
      ListRuleInfo::iterator it_list = rule_list.begin ();
      int i = 0;
      while (it_list != rule_list.end ())
	{
	  stru_prule_position coordinate = *it_list;
	  it_list++;
	  printf ("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
		  i++, coordinate.ply_idx, coordinate.rule_idx,
		  coordinate.ply_idx,
		  vector_policy[coordinate.ply_idx].BMap.getmap ().c_str ());
	}
    }
  printf (">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

  printf (">>>>>>>>>> The url rule information is as follows:\n");
  for (MapUrlRuleInfo::iterator it = map_url_rule.begin ();
       it != map_url_rule.end (); it++)
    {
      printf ("url = <%s>\n", it->first.c_str ());
      ListRuleInfo & rule_list = it->second;
      ListRuleInfo::iterator it_list = rule_list.begin ();
      int i = 0;
      while (it_list != rule_list.end ())
	{
	  stru_prule_position coordinate = *it_list;
	  it_list++;
	  printf ("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
		  i++, coordinate.ply_idx, coordinate.rule_idx,
		  coordinate.ply_idx,
		  vector_policy[coordinate.ply_idx].BMap.getmap ().c_str ());
	}
    }
  printf (">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

  printf (">>>>>>>>>> The proto rule information is as follows:\n");
  for (MapProtoRuleInfo::iterator it = map_proto_rule.begin ();
       it != map_proto_rule.end (); it++)
    {
      printf ("proto = <%d>\n", it->first);
      ListRuleInfo & rule_list = it->second;
      ListRuleInfo::iterator it_list = rule_list.begin ();
      int i = 0;
      while (it_list != rule_list.end ())
	{
	  stru_prule_position coordinate = *it_list;
	  it_list++;
	  printf ("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
		  i++, coordinate.ply_idx, coordinate.rule_idx,
		  coordinate.ply_idx,
		  vector_policy[coordinate.ply_idx].BMap.getmap ().c_str ());
	}
    }
  printf (">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

  printf (">>>>>>>>>> The sip rule information is as follows:\n");
  for (MapIPRuleInfo::iterator it = map_sip_rule.begin ();
       it != map_sip_rule.end (); it++)
    {
      printf ("sip = <%lu>\n", it->first);
      ListRuleInfo & rule_list = it->second;
      ListRuleInfo::iterator it_list = rule_list.begin ();
      int i = 0;
      while (it_list != rule_list.end ())
	{
	  stru_prule_position coordinate = *it_list;
	  it_list++;
	  printf ("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
		  i++, coordinate.ply_idx, coordinate.rule_idx,
		  coordinate.ply_idx,
		  vector_policy[coordinate.ply_idx].BMap.getmap ().c_str ());
	}
    }
  printf (">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");


  printf (">>>>>>>>>> The dip rule information is as follows:\n");
  for (MapIPRuleInfo::iterator it = map_dip_rule.begin ();
       it != map_dip_rule.end (); it++)
    {
      printf ("dip = <%lu>\n", it->first);
      ListRuleInfo & rule_list = it->second;
      ListRuleInfo::iterator it_list = rule_list.begin ();
      int i = 0;
      while (it_list != rule_list.end ())
	{
	  stru_prule_position coordinate = *it_list;
	  it_list++;
	  printf ("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
		  i++, coordinate.ply_idx, coordinate.rule_idx,
		  coordinate.ply_idx,
		  vector_policy[coordinate.ply_idx].BMap.getmap ().c_str ());
	}
    }
  printf (">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

  printf (">>>>>>>>>> The sport rule information is as follows:\n");
  for (MapPortRuleInfo::iterator it = map_sport_rule.begin ();
       it != map_sport_rule.end (); it++)
    {
      printf ("sport = <%u>\n", it->first);
      ListRuleInfo & rule_list = it->second;
      ListRuleInfo::iterator it_list = rule_list.begin ();
      int i = 0;
      while (it_list != rule_list.end ())
	{
	  stru_prule_position coordinate = *it_list;
	  it_list++;
	  printf ("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
		  i++, coordinate.ply_idx, coordinate.rule_idx,
		  coordinate.ply_idx,
		  vector_policy[coordinate.ply_idx].BMap.getmap ().c_str ());
	}
    }
  printf (">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

  printf (">>>>>>>>>> The dport rule information is as follows:\n");
  for (MapPortRuleInfo::iterator it = map_dport_rule.begin ();
       it != map_dport_rule.end (); it++)
    {
      printf ("dport = <%u>\n", it->first);
      ListRuleInfo & rule_list = it->second;
      ListRuleInfo::iterator it_list = rule_list.begin ();
      int i = 0;
      while (it_list != rule_list.end ())
	{
	  stru_prule_position coordinate = *it_list;
	  it_list++;
	  printf ("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
		  i++, coordinate.ply_idx, coordinate.rule_idx,
		  coordinate.ply_idx,
		  vector_policy[coordinate.ply_idx].BMap.getmap ().c_str ());
	}
    }
  printf (">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
}

inline void
cls_pkt_processor::add_rule_to_map (stru_prule_position coordinate,
				    stru_ISMS_policy_rule rule)
{
  if (rule.Rule_SubType == 1)	// host rule
    {
      string str_host (rule.Rule_Host);
      MapHostRuleInfo::iterator pos = map_site_rule.find (str_host);
      if (pos != map_site_rule.end ())
	{
	  printf ("\tThe host(%s) has been come up before!!!!!\n",
		  rule.Rule_Host);
	  ListRuleInfo & rule_list = pos->second;
	  rule_list.push_back (coordinate);
	}
      else
	{
	  printf ("\tThe host(%s) is a new one!!!!!\n", rule.Rule_Host);
	  ListRuleInfo rule_list;
	  rule_list.clear ();
	  rule_list.push_back (coordinate);

	  map_site_rule.insert (pair < string,
				ListRuleInfo > (str_host, rule_list));
	}
    }
  else if (rule.Rule_SubType == 2)	// url rule
    {
      string str_url (rule.Rule_Url);
      MapUrlRuleInfo::iterator pos = map_url_rule.find (str_url);
      if (pos != map_url_rule.end ())
	{
	  printf ("\tThe url(%s) has been come up before!!!!!\n",
		  rule.Rule_Url);
	  ListRuleInfo & rule_list = pos->second;
	  rule_list.push_back (coordinate);
	}
      else
	{
	  printf ("\tThe url(%s) is a new one!!!!!\n", rule.Rule_Url);
	  ListRuleInfo rule_list;
	  rule_list.clear ();
	  rule_list.push_back (coordinate);

	  map_url_rule.insert (pair < string,
			       ListRuleInfo > (str_url, rule_list));
	}
    }
  else if (rule.Rule_SubType == 3)
    {
    }
  else if (rule.Rule_SubType == 4)
    {
      int sip_num = rule.Rule_SipEnd - rule.Rule_SipStart + 1;
      unsigned long sip_start = rule.Rule_SipStart;
      for (int i = 0; i < sip_num; i++)
	{
	  unsigned long sip = sip_start + i;
	  MapIPRuleInfo::iterator pos = map_sip_rule.find (sip);
	  if (pos != map_sip_rule.end ())
	    {
	      printf ("\tThe sip(%lu) has been come up before!!!!!\n", sip);
	      ListRuleInfo & rule_list = pos->second;
	      rule_list.push_back (coordinate);
	    }
	  else
	    {
	      printf ("\tThe sip(%lu) is a new one!!!!!\n", sip);
	      ListRuleInfo rule_list;
	      rule_list.clear ();
	      rule_list.push_back (coordinate);

	      map_sip_rule.insert (pair < unsigned long,
				   ListRuleInfo > (sip, rule_list));
	    }
	}
    }
  else if (rule.Rule_SubType == 5)
    {
      int dip_num = rule.Rule_DipEnd - rule.Rule_DipStart + 1;
      unsigned long dip_start = rule.Rule_DipStart;
      for (int i = 0; i < dip_num; i++)
	{
	  unsigned long dip = dip_start + i;
	  MapIPRuleInfo::iterator pos = map_dip_rule.find (dip);
	  if (pos != map_dip_rule.end ())
	    {
	      printf ("\tThe dip(%lu) has been come up before!!!!!\n", dip);
	      ListRuleInfo & rule_list = pos->second;
	      rule_list.push_back (coordinate);
	    }
	  else
	    {
	      printf ("\tThe dip(%lu) is a new one!!!!!\n", dip);
	      ListRuleInfo rule_list;
	      rule_list.clear ();
	      rule_list.push_back (coordinate);

	      map_dip_rule.insert (pair < unsigned long,
				   ListRuleInfo > (dip, rule_list));
	    }
	}
    }
  else if (rule.Rule_SubType == 6)
    {
      int port_num = rule.Rule_SportEnd - rule.Rule_SportStart + 1;
      unsigned int port_start = rule.Rule_SportStart;
      for (int i = 0; i < port_num; i++)
	{
	  unsigned int port = port_start + i;
	  MapPortRuleInfo::iterator pos = map_sport_rule.find (port);
	  if (pos != map_sport_rule.end ())
	    {
	      printf ("\tThe sport(%u) hash been come up before!!!!!\n",
		      port);
	      ListRuleInfo & rule_list = pos->second;
	      rule_list.push_back (coordinate);
	    }
	  else
	    {
	      printf ("\tThe sport(%u) is a new one!!!!!\n", port);
	      ListRuleInfo rule_list;
	      rule_list.clear ();
	      rule_list.push_back (coordinate);

	      map_sport_rule.insert (pair < unsigned int,
				     ListRuleInfo > (port, rule_list));
	    }
	}
    }
  else if (rule.Rule_SubType == 7)
    {
      int port_num = rule.Rule_DportEnd - rule.Rule_DportStart + 1;
      unsigned int port_start = rule.Rule_SportStart;
      for (int i = 0; i < port_num; i++)
	{
	  unsigned int port = port_start + i;
	  MapPortRuleInfo::iterator pos = map_dport_rule.find (port);
	  if (pos != map_dport_rule.end ())
	    {
	      printf ("\tThe dport(%u) hash been come up before!!!!!\n",
		      port);
	      ListRuleInfo & rule_list = pos->second;
	      rule_list.push_back (coordinate);
	    }
	  else
	    {
	      printf ("\tThe sport(%u) is a new one!!!!!\n", port);
	      ListRuleInfo rule_list;
	      rule_list.clear ();
	      rule_list.push_back (coordinate);

	      map_dport_rule.insert (pair < unsigned int,
				     ListRuleInfo > (port, rule_list));
	    }
	}
    }
  else if (rule.Rule_SubType == 8)
    {
      int proto = rule.Rule_ProtoL4;
      MapProtoRuleInfo::iterator pos = map_proto_rule.find (proto);
      if (pos != map_proto_rule.end ())
	{
	  printf ("\tThe proto(%d) has been come up before!!!!!\n", proto);
	  ListRuleInfo & rule_list = pos->second;
	  rule_list.push_back (coordinate);
	}
      else
	{
	  printf ("\tThe proto(%d) is a new one!!!!!\n", proto);
	  ListRuleInfo rule_list;
	  rule_list.clear ();
	  rule_list.push_back (coordinate);

	  map_proto_rule.insert (pair < int,
				 ListRuleInfo > (proto, rule_list));
	}
    }
}



ListRuleInfo
  cls_pkt_processor::do_keyword_match (const LLHeadStru * pStruLLHead,
				       const L3HeadStru * pStruL3Head,
				       //const L4HeadUnion *pUnionL4Head,
				       const TCPHeadStru * pStruTCPHead,
				       unsigned int sip,
				       unsigned short sport,
				       unsigned int dip,
				       unsigned short dport,
				       unsigned char *data_buf,
				       unsigned int data_len)
{
  ListRuleInfo list_rule_bingo;
  list_rule_bingo.clear ();

  unsigned long ret = 0;
  unsigned char search_rslt[SIZE_SEARCH_RSLT];
  bzero (search_rslt, sizeof (search_rslt));
  //printf(">>>>>>>>>>>>>>>>>>> search_rslt: sizeof = %d bytes\n", SIZE_SEARCH_RSLT);

  unsigned char temp_buf[65535];
  bzero (temp_buf, sizeof (temp_buf));

  int temp_buf_len = (data_len < 65535) ? (data_len) : (65534);

  memcpy (temp_buf, data_buf, temp_buf_len);

#ifdef __DEBUG_MWM_FIND_STRING
  //printf("content to be matched: len = %d, (((((%s)))))\n", temp_buf_len, temp_buf);
#endif

  ret =
    beap_mwm_search_search (mwm_handle, &search_rslt[0],
			    (signed char *) temp_buf, temp_buf_len);
  if (ret == 0)
    {
      //printf("match function: ret == 0, no match, return\n", ret);
    }
  else
    {
      //printf("match function: ret = %u, match some rules\n", ret);
    }

  int i = 0, j = 0;

  //printf("size_per_rule_rslt = %d\n", SIZE_PER_RULE_RSLT);
  for (i = 0; i < SIZE_SEARCH_RSLT; i++)
    {
      unsigned char temp = search_rslt[i];
      if (temp == 0)
	{
	  continue;
	}
      stru_prule_position coordinate =
	{ result_info_list[i].rule_id, result_info_list[i].key_id };
      list_rule_bingo.push_back (coordinate);
    }

  return list_rule_bingo;
}

void
cls_pkt_processor::send_L3_reset (int sock,
				  unsigned long sip,
				  unsigned long dip,
				  unsigned int sport,
				  unsigned int dport,
				  unsigned long seq,
				  unsigned long next_ack_seq)
{
  L3HeadStru *L3Head = NULL;
  TCPHeadStru *L4Head = NULL;
  char buf[1500];
  char sp_pseudo_ip_construct[1500];
  struct pseudo_IP_header *sp_help_pseudo;

  bzero (buf, sizeof (buf));
  bzero (sp_pseudo_ip_construct, sizeof (sp_pseudo_ip_construct));

  L3Head = (L3HeadStru *) buf;
  //L3Head->version = (4 << 4) | (20 / 4);
  L3Head->version = 0x45;
  L3Head->diff_serv_field = 0;
  L3Head->total_len = htons (20 + 20);
  L3Head->total_len = htons (40);
  L3Head->identification = htons (12545);
  L3Head->flag = 0x0;
  L3Head->TTL = 69;
  L3Head->protocol = 6;
  L3Head->header_checksum = in_cksum ((unsigned short *) buf, 20);
  L3Head->source_addr = htonl (sip);
  L3Head->dest_addr = htonl (dip);
  sp_help_pseudo = (struct pseudo_IP_header *) sp_pseudo_ip_construct;

  L4Head = (TCPHeadStru *) (buf + 20);
  L4Head->header_len = 0x50;
  L4Head->flags = 0x14;
  L4Head->seq_num = htonl (seq);
  L4Head->ack_num = htonl (next_ack_seq);
  L4Head->source_port = htons (sport);
  L4Head->dest_port = htons (dport);
  L4Head->win_size = 0;//htons (0x7c00);

  sp_help_pseudo->source = htonl (sip);
  sp_help_pseudo->destination = htonl (dip);
  sp_help_pseudo->zero_byte = 0;
  sp_help_pseudo->protocol = 6;
  sp_help_pseudo->TCP_UDP_len = htons (20);

  memcpy (sp_pseudo_ip_construct + 12, L4Head, 20);
  L4Head->checksum =
    in_cksum ((unsigned short *) sp_pseudo_ip_construct, 12 + 20);

  struct sockaddr_in sp_server;
  int HEAD_BASE = 20;

  bzero (&sp_server, sizeof (sp_server));
  sp_server.sin_family = AF_INET;
  sp_server.sin_addr.s_addr = htonl (dip);

  int sp_status = sendto (sock, (char *) buf, HEAD_BASE + 20, 0,
			  (struct sockaddr *) &sp_server,
			  sizeof (struct sockaddr));
  if (sp_status == -1)
    printf ("send reset packet error!!!!!\n");
  //else
    //printf ("send reset packet: from(%u:%d) to (%u:%d)\n", sip, sport, dip,
	 //   dport);

}

unsigned short
cls_pkt_processor::in_cksum (unsigned short *addr, int len)
{
  register int nleft = len;
  register unsigned short *w = addr;
  register int sum = 0;
  unsigned short answer = 0;

  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

  if (nleft == 1)
    {
      *(unsigned char *) (&answer) = *(unsigned char *) w;
      sum += answer;
    }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;

  return (answer);
}


char
cls_pkt_processor::do_action_by_action (ENUM_PKT_ACTION action,
					const L3HeadStru * pStruL3Head,
					const TCPHeadStru * pStruTCPHead,
					int proto,
					unsigned long sip,
					unsigned long dip,
					unsigned int sport,
					unsigned int dport,
					unsigned char *host)
{
  int payload_len = 0;
  switch (action)
    {
    case PKT_RST:
	payload_len = pStruL3Head->total_len - (pStruL3Head->version & 0x0f)*4 - (pStruTCPHead->header_len >> 4)*4;
if(payload_len == 0)
	payload_len = 1;
      send_L3_reset (sock_reset, dip, sip, dport, sport,
		     pStruTCPHead->ack_num,
		     pStruTCPHead->seq_num + payload_len);
      //send_L3_reset (sock_reset, sip, dip, sport, dport,
		//     pStruTCPHead->seq_num + payload_len,
		 //    pStruTCPHead->ack_num);
      break;
    case PKT_RET:
      break;
    case PKT_DEAL:
      break;
    default:
      break;
    }

  return 0;
}


char
cls_pkt_processor::do_action_by_policy (stru_ISMS_policy policy,
					const L3HeadStru * pStruL3Head,
					const TCPHeadStru * pStruTCPHead,
					int proto,
					unsigned long sip,
					unsigned long dip,
					unsigned int sport,
					unsigned int dport,
					char *host, char *url, char *keyword)
{
  /*
     printf("do_action: policy information is as follows:\n");
     printf("\tMessageNo: %u\n", policy.MsgNo);
     printf("\tCommandID: %s\n", policy.CmdID);
     printf("\tPolicy_Type: %d\n", policy.Type);
     printf("\tPolicy_BlockFlag: %d\n", policy.BlockFlag);
     printf("\tPolicy_LogFlag: %d\n", policy.LogFlag);
     printf("\tPolicy_BMap: %s\n", policy.BMap.getmap().c_str());
   */

//  return policy.BlockFlag;

  if (policy.BlockFlag)
    {
	  int payload_len = pStruL3Head->total_len - (pStruL3Head->version & 0x0f)*4 - (pStruTCPHead->header_len >> 4)*4;
	  if(payload_len == 0)
			payload_len = 1;
      send_L3_reset (sock_reset, dip, sip, dport, sport,
		     pStruTCPHead->ack_num,
		     pStruTCPHead->seq_num + payload_len);
      send_L3_reset (sock_reset, sip, dip, sport, dport,
		     pStruTCPHead->seq_num + payload_len,
		     pStruTCPHead->ack_num);

    }
  stru_ud_log ud_log;
  bzero (&ud_log, sizeof (ud_log));

  if (policy.LogFlag)
    {
      unsigned char *log_packet = NULL;
      int log_packet_len = 0;
      if (policy.Type == 1)
	{
	  //printf ("assemble_monitor_log_packet..............\n");
	  log_packet_len =
	    assemble_log_packet (policy.Type, sip, dip, sport, dport, host,
				 url, keyword, &ud_log);
	}
      else if (policy.Type == 2)
	{
	  printf ("assemble_filter_log_packet..............\n");
	  log_packet_len =
	    assemble_log_packet (policy.Type, sip, dip, sport, dport, host,
				 url, keyword, &ud_log);
	}
      else
	{
	}

      if (log_packet_len > 0)
	{
	  sem_wait (&send_buf_sem);
	  send_buf->push_back (ud_log);
	  sem_post (&send_buf_sem);
	  struct timeval t1, t2;
	  gettimeofday (&t1, NULL);
	  //tcp_comm->send_msg((char*)"127.0.0.1", client_port_ud_log, log_packet, log_packet_len);
	  //tcp_comm->send_msg((char*)"127.0.0.1", 60000, log_packet, log_packet_len);
	  gettimeofday (&t2, NULL);
//delt12 +=
//          (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);


	  //printf ("free log_packet.................\n");
	  //free (log_packet);
	}
    }

  return policy.BlockFlag;
}


int
cls_pkt_processor::assemble_log_packet (char type, unsigned int sip,
					unsigned int dip,
					unsigned short sport,
					unsigned short dport, char *host,
					char *url, char *keyword,
					stru_ud_log * ud_log_info)
{
  int len = 0;
  ud_log_info->type = type;
  ud_log_info->SourceIP_Length = 0x04;
  ud_log_info->SrcIp =
    (unsigned char *) calloc ((int) (ud_log_info->SourceIP_Length), 1);
  memcpy (ud_log_info->SrcIp, &sip, ud_log_info->SourceIP_Length);

  ud_log_info->DestinationIP_Length = 0x04;
  ud_log_info->DestIp =
    (unsigned char *) calloc ((int) (ud_log_info->DestinationIP_Length), 1);
  memcpy (ud_log_info->DestIp, &dip, ud_log_info->DestinationIP_Length);

  ud_log_info->SrcPort = sport;
  ud_log_info->DestPort = dport;

  if (host != NULL)
    {
      len = strlen (host);
      ud_log_info->DomainName = (unsigned char *) calloc (len, 1);
      memcpy (ud_log_info->DomainName, host, len);
    }
  ud_log_info->Title = (unsigned char *) calloc (8, 1);
  memcpy (ud_log_info->Title, "safe_log", 8);

  ud_log_info->Content = (unsigned char *) calloc (14, 1);
  memcpy (ud_log_info->Content, "content of log", 14);

  if (url != NULL)
    {
      len = strlen (url);
      ud_log_info->Url = (unsigned char *) calloc (len, 1);
      memcpy (ud_log_info->Url, url, len);
    }
  ud_log_info->Attachmentfile_Num = 2;
  ud_log_info->attach_content_t =
    (struct monitor_attach_content *) calloc (ud_log_info->
					      Attachmentfile_Num *
					      sizeof (struct
						      monitor_attach_content),
					      1);
  ud_log_info->attach_content_t[0].AttachmentfileName_Length = 11;
  ud_log_info->attach_content_t[0].AttachmentfileName =
    (unsigned char *) calloc (11, 1);
  memcpy (ud_log_info->attach_content_t[0].AttachmentfileName, "Attachment1",
	  11);
  ud_log_info->attach_content_t[1].AttachmentfileName_Length = 11;
  ud_log_info->attach_content_t[1].AttachmentfileName =
    (unsigned char *) calloc (11, 1);
  memcpy (ud_log_info->attach_content_t[1].AttachmentfileName, "Attachment2",
	  11);
  ud_log_info->GatherTime = time (NULL);
  if (keyword != NULL)
    {
      len = strlen (keyword);
      ud_log_info->keyword = (unsigned char *) calloc (len, 1);
      memcpy (ud_log_info->keyword, keyword, len);
    }
  return 1;
}

#if 0
int
cls_pkt_processor::assemble_monitor_log_packet (unsigned int sip,
						unsigned int dip,
						unsigned short sport,
						unsigned short dport,
						char *host, char *url,
						char *keyword,
						unsigned char **out_buf)
{
  char str1[128], str2[128];
//static int j = 0;
  struct timeval t1, t2;
  gettimeofday (&t1, NULL);
  unsigned char *msg_to_send_tmp = NULL;
  unsigned long buf_bytes = 0;
  short len = 0;

  struct ud_header ud_header_for_monitor;
  struct monitor_log_info ud_log_info_for_monitor;
  bzero (&ud_header_for_monitor, sizeof (struct ud_header));
  bzero (&ud_log_info_for_monitor, sizeof (struct monitor_log_info));

  ud_header_for_monitor.Ver_and_Resv = 0x01;
  memcpy (ud_header_for_monitor.Proto_Signature, "CUD", 3);
  //sprintf((char *)(ud_header_for_monitor.Proto_Signature),"%03d",++j);
  ud_header_for_monitor.DevID = 0x02;
  memcpy (ud_header_for_monitor.DeviceSerialNo, "123", 3);
  ud_header_for_monitor.Packet_Type = 0x01;
  ud_header_for_monitor.Packet_Subtype = 0xe0;
  memcpy (ud_header_for_monitor.Resv, "re", 2);

  memcpy (ud_log_info_for_monitor.CommandID, "command", 7);
  ud_log_info_for_monitor.House_ID_Length = 0x05;
  ud_log_info_for_monitor.House_ID =
    (unsigned char *)
    calloc ((int) (ud_log_info_for_monitor.House_ID_Length), 1);
  memcpy (ud_log_info_for_monitor.House_ID, "house", 5);

  ud_log_info_for_monitor.SourceIP_Length = 0x04;
  ud_log_info_for_monitor.SrcIp =
    (unsigned char *)
    calloc ((int) (ud_log_info_for_monitor.SourceIP_Length), 1);
  memcpy (ud_log_info_for_monitor.SrcIp, &sip,
	  ud_log_info_for_monitor.SourceIP_Length);

  ud_log_info_for_monitor.DestinationIP_Length = 0x04;
  ud_log_info_for_monitor.DestIp =
    (unsigned char *)
    calloc ((int) (ud_log_info_for_monitor.DestinationIP_Length), 1);
  memcpy (ud_log_info_for_monitor.DestIp, &dip,
	  ud_log_info_for_monitor.DestinationIP_Length);

  ud_log_info_for_monitor.SrcPort = htons (sport);
  ud_log_info_for_monitor.DestPort = htons (dport);

  len = (host == NULL ? 1 : strlen (host));
  ud_log_info_for_monitor.DomainName_Length = htons (len);
  ud_log_info_for_monitor.DomainName = (unsigned char *) calloc (len, 1);
  memcpy (ud_log_info_for_monitor.DomainName, host, len);

  ud_log_info_for_monitor.ProxyType_Flag = htons (0);
  ud_log_info_for_monitor.Title_Length = htons (8);
  ud_log_info_for_monitor.Title = (unsigned char *) calloc (8, 1);
  memcpy (ud_log_info_for_monitor.Title, "safe_log", 8);
  ud_log_info_for_monitor.Content_Length = htonl (14);
  ud_log_info_for_monitor.Content = (unsigned char *) calloc (14, 1);
  memcpy (ud_log_info_for_monitor.Content, "content of log", 14);
  len = (url == NULL ? 1 : strlen (url));
  ud_log_info_for_monitor.Url_Length = htons (len);
  ud_log_info_for_monitor.Url = (unsigned char *) calloc (len, 1);
  memcpy (ud_log_info_for_monitor.Url, url, len);
  ud_log_info_for_monitor.Attachmentfile_Num = 2;
  ud_log_info_for_monitor.attach_content_t =
    (struct monitor_attach_content *)
    calloc (ud_log_info_for_monitor.Attachmentfile_Num *
	    sizeof (struct monitor_attach_content), 1);
  ud_log_info_for_monitor.attach_content_t[0].AttachmentfileName_Length =
    htons (11);
  ud_log_info_for_monitor.attach_content_t[0].AttachmentfileName =
    (unsigned char *) calloc (11, 1);
  memcpy (ud_log_info_for_monitor.attach_content_t[0].AttachmentfileName,
	  "Attachment1", 11);
  ud_log_info_for_monitor.attach_content_t[1].AttachmentfileName_Length =
    htons (11);
  ud_log_info_for_monitor.attach_content_t[1].AttachmentfileName =
    (unsigned char *) calloc (11, 1);
  memcpy (ud_log_info_for_monitor.attach_content_t[1].AttachmentfileName,
	  "Attachment2", 11);
  ud_log_info_for_monitor.GatherTime = htonl (time (NULL));

  buf_bytes =
    sizeof (struct ud_header) + sizeof (ud_log_info_for_monitor.CommandID) +
    sizeof (ud_log_info_for_monitor.House_ID_Length) +
    (unsigned int) ud_log_info_for_monitor.House_ID_Length +
    sizeof (ud_log_info_for_monitor.SourceIP_Length) +
    (unsigned int) ud_log_info_for_monitor.SourceIP_Length +
    sizeof (ud_log_info_for_monitor.DestinationIP_Length) +
    (unsigned int) ud_log_info_for_monitor.DestinationIP_Length +
    sizeof (ud_log_info_for_monitor.SrcPort) +
    sizeof (ud_log_info_for_monitor.DestPort) +
    sizeof (ud_log_info_for_monitor.DomainName_Length) +
    (unsigned int) (ntohs (ud_log_info_for_monitor.DomainName_Length)) +
    sizeof (ud_log_info_for_monitor.ProxyType_Flag);

  if ((ntohs (ud_log_info_for_monitor.ProxyType_Flag)) != 0)
    {
      buf_bytes =
	buf_bytes + sizeof (ud_log_info_for_monitor.ProxyType) +
	sizeof (ud_log_info_for_monitor.ProxyIp_Length) +
	(unsigned int) ud_log_info_for_monitor.ProxyIp_Length +
	sizeof (ud_log_info_for_monitor.ProxyPort);
    }

  buf_bytes =
    buf_bytes + sizeof (ud_log_info_for_monitor.Title_Length) +
    (unsigned int) (ntohs (ud_log_info_for_monitor.Title_Length)) +
    sizeof (ud_log_info_for_monitor.Content_Length) +
    (unsigned int) (ntohl (ud_log_info_for_monitor.Content_Length)) +
    sizeof (ud_log_info_for_monitor.Url_Length) +
    (unsigned int) (ntohs (ud_log_info_for_monitor.Url_Length)) +
    sizeof (ud_log_info_for_monitor.Attachmentfile_Num);

  if (ud_log_info_for_monitor.Attachmentfile_Num != 0)
    {
      for (int i = 0; i < ud_log_info_for_monitor.Attachmentfile_Num; i++)
	{
	  buf_bytes =
	    buf_bytes +
	    sizeof (ud_log_info_for_monitor.
		    attach_content_t[i].AttachmentfileName_Length) +
	    (unsigned
	     int) (ntohs (ud_log_info_for_monitor.
			  attach_content_t[i].AttachmentfileName_Length));
	}
    }

  buf_bytes = buf_bytes + sizeof (ud_log_info_for_monitor.GatherTime);
  buf_bytes += strlen (keyword) + 1;
  ud_header_for_monitor.Packet_Length = buf_bytes;

  *out_buf =
    (unsigned char *) calloc (sizeof (unsigned char) * buf_bytes + 1, 1);
  msg_to_send_tmp = *out_buf;

  ud_header_for_monitor.Packet_Length =
    htonl (ud_header_for_monitor.Packet_Length);
  memcpy (*out_buf, &ud_header_for_monitor, sizeof (struct ud_header));

  msg_to_send_tmp = msg_to_send_tmp + sizeof (struct ud_header);
  memcpy (msg_to_send_tmp, ud_log_info_for_monitor.CommandID, 10);
  msg_to_send_tmp = msg_to_send_tmp + 10;
  memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.House_ID_Length), 1);
  msg_to_send_tmp = msg_to_send_tmp + 1;
  memcpy (msg_to_send_tmp, ud_log_info_for_monitor.House_ID,
	  (int) ud_log_info_for_monitor.House_ID_Length);
  msg_to_send_tmp =
    msg_to_send_tmp + (int) ud_log_info_for_monitor.House_ID_Length;
  memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.SourceIP_Length), 1);
  msg_to_send_tmp = msg_to_send_tmp + 1;
  memcpy (msg_to_send_tmp, ud_log_info_for_monitor.SrcIp,
	  (int) ud_log_info_for_monitor.SourceIP_Length);
  msg_to_send_tmp =
    msg_to_send_tmp + (int) ud_log_info_for_monitor.SourceIP_Length;
  memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.DestinationIP_Length),
	  1);
  msg_to_send_tmp = msg_to_send_tmp + 1;
  memcpy (msg_to_send_tmp, ud_log_info_for_monitor.DestIp,
	  (int) ud_log_info_for_monitor.DestinationIP_Length);
  msg_to_send_tmp =
    msg_to_send_tmp + (int) ud_log_info_for_monitor.DestinationIP_Length;
  memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.SrcPort), 2);
  msg_to_send_tmp = msg_to_send_tmp + 2;
  memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.DestPort), 2);
  msg_to_send_tmp = msg_to_send_tmp + 2;
  memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.DomainName_Length), 2);
  msg_to_send_tmp = msg_to_send_tmp + 2;

  if ((ntohs (ud_log_info_for_monitor.DomainName_Length)) != 0)
    {
      memcpy (msg_to_send_tmp, ud_log_info_for_monitor.DomainName,
	      (int) (ntohs (ud_log_info_for_monitor.DomainName_Length)));
      msg_to_send_tmp =
	msg_to_send_tmp +
	(int) (ntohs (ud_log_info_for_monitor.DomainName_Length));
    }
  memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.ProxyType_Flag), 2);
  msg_to_send_tmp = msg_to_send_tmp + 2;
  if ((ntohs (ud_log_info_for_monitor.ProxyType_Flag)) != 0)
    {
      memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.ProxyType), 2);
      msg_to_send_tmp = msg_to_send_tmp + 2;
      memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.ProxyIp_Length), 1);
      msg_to_send_tmp = msg_to_send_tmp + 1;
      memcpy (msg_to_send_tmp, ud_log_info_for_monitor.ProxyIp,
	      (int) ud_log_info_for_monitor.ProxyIp_Length);
      msg_to_send_tmp =
	msg_to_send_tmp + (int) ud_log_info_for_monitor.ProxyIp_Length;
      memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.ProxyPort), 2);
      msg_to_send_tmp = msg_to_send_tmp + 2;
    }
  memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.Title_Length), 2);
  msg_to_send_tmp = msg_to_send_tmp + 2;
  if ((ntohs (ud_log_info_for_monitor.Title_Length)) != 0)
    {
      memcpy (msg_to_send_tmp, ud_log_info_for_monitor.Title,
	      (int) (ntohs (ud_log_info_for_monitor.Title_Length)));
      msg_to_send_tmp =
	msg_to_send_tmp +
	(int) (ntohs (ud_log_info_for_monitor.Title_Length));
    }
  memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.Content_Length), 4);
  msg_to_send_tmp = msg_to_send_tmp + 4;

  if ((ntohl (ud_log_info_for_monitor.Content_Length)) != 0)
    {
      memcpy (msg_to_send_tmp, ud_log_info_for_monitor.Content,
	      (int) (ntohl (ud_log_info_for_monitor.Content_Length)));
      msg_to_send_tmp =
	msg_to_send_tmp +
	(int) (ntohl (ud_log_info_for_monitor.Content_Length));
    }

  memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.Url_Length), 2);
  msg_to_send_tmp = msg_to_send_tmp + 2;

  if ((ntohs (ud_log_info_for_monitor.Url_Length)) != 0)
    {
      memcpy (msg_to_send_tmp, ud_log_info_for_monitor.Url,
	      (int) (ntohs (ud_log_info_for_monitor.Url_Length)));
      msg_to_send_tmp =
	msg_to_send_tmp + (int) (ntohs (ud_log_info_for_monitor.Url_Length));
    }

  memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.Attachmentfile_Num), 1);
  msg_to_send_tmp = msg_to_send_tmp + 1;
  if (ud_log_info_for_monitor.Attachmentfile_Num != 0)
    {
      for (int i = 0; i < ud_log_info_for_monitor.Attachmentfile_Num; i++)
	{
	  memcpy (msg_to_send_tmp,
		  &(ud_log_info_for_monitor.
		    attach_content_t[i].AttachmentfileName_Length), 2);
	  msg_to_send_tmp = msg_to_send_tmp + 2;
	  memcpy (msg_to_send_tmp,
		  ud_log_info_for_monitor.
		  attach_content_t[i].AttachmentfileName,
		  ntohs (ud_log_info_for_monitor.
			 attach_content_t[i].AttachmentfileName_Length));
	  msg_to_send_tmp =
	    msg_to_send_tmp +
	    ntohs (ud_log_info_for_monitor.
		   attach_content_t[i].AttachmentfileName_Length);
	}
    }

  memcpy (msg_to_send_tmp, &(ud_log_info_for_monitor.GatherTime), 4);
  msg_to_send_tmp = msg_to_send_tmp + 4;
  char keyword_len = strlen (keyword);
  memcpy (msg_to_send_tmp, &keyword_len, 1);
  msg_to_send_tmp += 1;
  memcpy (msg_to_send_tmp, keyword, strlen (keyword));

  gettimeofday (&t2, NULL);

  delt11 += (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
  return buf_bytes;

}
#endif

int
cls_pkt_processor::assemble_filter_log_packet (unsigned char **out_buf)
{
  unsigned char *msg_to_send_tmp = NULL;
  unsigned long buf_bytes = 0;

  return buf_bytes;
}

void
cls_pkt_processor::Initialize ()
{
  int ret = 0;
  ISMS_ply_upd_time = 0;
  delt1 = 0;
  delt2 = 0;
  delt3 = 0;
  delt4 = 0;
  delt5 = 0;
  delt6 = 0;
  delt7 = 0;
  delt8 = 0;
  delt9 = 0;
  delt10 = 0;
  delt11 = 0;
  delt12 = 0;
  http_num = 0;
  tcp_num = 0;
  send_buf_index = 0;
  cur_time = last_time = time (NULL);
  send_buf_a = new vector < stru_ud_log >;
  send_buf_b = new vector < stru_ud_log >;
  send_buf = send_buf_a;
  sem_init (&send_buf_sem, 0, 1);
  sem_init (&conn_hash_sem, 0, 1);
  result_info_list.clear ();
  bzero (&ud_head, sizeof (struct ud_header));

  ud_head.Ver_and_Resv = 0x01;
  memcpy (ud_head.Proto_Signature, "CUD", 3);
  ud_head.DevID = 0x02;
  memcpy (ud_head.DeviceSerialNo, "123", 3);
  ud_head.Packet_Type = 0x01;
  ud_head.Packet_Subtype = 0xe0;
  memcpy (ud_head.Resv, "re", 2);
  bzero (command_house, sizeof (command_house));
  memcpy (command_house, "command", strlen ("command"));
  *(unsigned char *) (command_house + 10) = 5;
  memcpy (command_house + 10 + 1, "house", strlen ("house"));

  command_house_len = 10 + 1 + strlen ("house");



  if ((conn_hash =
       create_hash (SIZE_CACHE_CONN_HASH, conn_hash_func,
		    conn_comp_func)) == NULL)
    {
      printf ("conn_hash: create_hash error, exit!\n");
      exit (1);
    }
  if (ret =
      ClsDBOperation.connect_db ("localhost", "root", "tma1100", "db_idc"))
    {
      printf ("Initialize(): connect database failed, exit!!!!!\n");
      exit (1);
    }

  sock_reset = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock_reset == -1)
    {
      printf ("Initialize(): create sock_reset error, exit!!!!!\n");
      exit (1);
    }

  printf ("CDPDKRingReader Initialize(): initialize mwm_handle\n");
  mwm_handle = NULL;
  mwm_handle = mwmNew ();

  bzero (house_id, sizeof (house_id));
  bzero (house_ip, sizeof (house_ip));
  ClsDBOperation.get_EU_CommInfo (house_id);
  printf ("Initialize(): read_house_id over, %s %s\n", house_id, house_ip);

  load_ISMS_policies ();

  serv_port_policy_update = client_port_ud_log = client_port_ud_attach = 0;
  read_comm_conf_from_file ();
  printf ("Initialize(): read comm conf, %d %d %d\n", serv_port_policy_update,
	  client_port_ud_log, client_port_ud_attach);

  udp_comm = new CUDPServer (serv_port_policy_update);
  tcp_comm = new CTCPServer ();
  printf
    ("Initialize(): UDPServer and TCPServer initialization over.......\n");


  map_result.clear ();
  pthread_t hdl_temp;
  pthread_create (&hdl_temp, NULL, radom_work_func, this);
  //pthread_create (&hdl_temp, NULL, send_msg_thread_work, this);

  printf ("Initialize(): initialization working over!\n");


  cap_pkt_cnt = 0;
  num_tcp_conn = 0;
  num_http_req_pkt_recv = 0;
  num_http_resp_pkt_recv = 0;
  num_http_req_sdu_data = 0;
  num_http_resp_sdu_data = 0;
  num_http_req_data = 0;
  num_http_resp_data = 0;
  num_http_other_data = 0;

}

void *
cls_pkt_processor::radom_work_func (void *arg)
{
  cls_pkt_processor *obj = (cls_pkt_processor *) arg;
  obj->do_radom_work (arg);
}

void *
cls_pkt_processor::send_msg_thread_work (void *arg)
{
  cls_pkt_processor *obj = (cls_pkt_processor *) arg;
  //obj->send_msg_thread(arg);
}

void
cls_pkt_processor::send_msg_thread (void *arg)
{
  return;
}

unsigned char *
cls_pkt_processor::get_send_data (stru_ud_log ud_log)
{
  int packet_len = 0, url_len = 0, host_len = 0, title_len = 0, content_len =
    0, keyword_len;
  unsigned char *buf = NULL, *p = NULL;

  if (ud_log.DomainName != NULL)
    {
      host_len = strlen ((const char *) (ud_log.DomainName));
    }
  if (ud_log.Url != NULL)
    {
      url_len = strlen ((const char *) (ud_log.Url));
    }
  if (ud_log.Title != NULL)
    {
      title_len = strlen ((const char *) (ud_log.Title));
    }
  if (ud_log.Content != NULL)
    {
      content_len = strlen ((const char *) (ud_log.Content));
    }
  if (ud_log.keyword != NULL)
    {
      keyword_len = strlen ((const char *) (ud_log.keyword));
    }


  packet_len = command_house_len + 1	//src_ip len
    + ud_log.SourceIP_Length	//src ip
    + 1				//dest ip len 
    + ud_log.DestinationIP_Length	//dest ip
    + 2				//src port
    + 2				//dest port
    + 2				//host len
    + host_len			//host
    +2				//proxy_flag
    + 2				//title_len
    + title_len + 4		//content len       
    + content_len + 2		//url len
    + url_len + 1;		//num len
  if (ud_log.Attachmentfile_Num != 0)
    {
      for (int i = 0; i < ud_log.Attachmentfile_Num; i++)
	{
	  packet_len +=
	    2 + ud_log.attach_content_t[i].AttachmentfileName_Length;
	}
    }

  packet_len += 4		//time
    + 1				//keyword len
    + keyword_len;
  buf = (unsigned char *) calloc (sizeof (struct ud_header) + packet_len, 1);
  p = buf;

  ud_head.Packet_Length = packet_len;
  MEMCPY_STR (p, &ud_head, sizeof (struct ud_header));
  MEMCPY_1BYTE (p, command_house_len, 1);
  MEMCPY_STR (p, command_house, command_house_len);
  MEMCPY_1BYTE (p, ud_log.SourceIP_Length, 1);
  MEMCPY_STR (p, ud_log.SrcIp, ud_log.SourceIP_Length);
  MEMCPY_1BYTE (p, ud_log.DestinationIP_Length, 1);
  MEMCPY_STR (p, ud_log.DestIp, ud_log.DestinationIP_Length);
  MEMCPY_2BYTE (p, ud_log.SrcPort, 2);
  MEMCPY_2BYTE (p, ud_log.DestPort, 2);
  MEMCPY_2BYTE (p, host_len, 2);

  if (host_len != 0)
    MEMCPY_STR (p, ud_log.DomainName, host_len);


  MEMCPY_2BYTE (p, 0, 2);
  MEMCPY_2BYTE (p, title_len, 2);
  if (title_len != 0)
    MEMCPY_STR (p, ud_log.Title, title_len);

  MEMCPY_4BYTE (p, content_len, 4);

  if (content_len != 0)
    MEMCPY_STR (p, ud_log.Content, content_len);

  MEMCPY_2BYTE (p, url_len, 2);
  if (url_len != 0)
    MEMCPY_STR (p, ud_log.Url, url_len);

  MEMCPY_1BYTE (p, ud_log.Attachmentfile_Num, 1);

  if (ud_log.Attachmentfile_Num != 0)
    {
      for (int i = 0; i < ud_log.Attachmentfile_Num; i++)
	{
	  MEMCPY_2BYTE (p,
			ud_log.attach_content_t[i].AttachmentfileName_Length,
			2);
	  MEMCPY_STR (p, ud_log.attach_content_t[i].AttachmentfileName,
		      ud_log.attach_content_t[i].AttachmentfileName_Length);
	}
    }

  MEMCPY_2BYTE (p, ud_log.GatherTime, 2);
  MEMCPY_1BYTE (p, keyword_len, 1);
  MEMCPY_STR (p, ud_log.keyword, keyword_len);
  return buf;
}

void
cls_pkt_processor::do_radom_work (void *arg)
{
  printf ("do_radom_work thread is running.......\n");
  static int file_index = 0;
  struct timeval t1, t2;
  char str1[128], str2[128];
  stru_ud_log info;

  while (1)
    {
      sleep (5);
      cur_time = time (NULL);
	  clear_conn_hash();
      printf ("################packet_num=%u,http_num=%d,tcp_num = %d\n",
	      cap_pkt_cnt, http_num, tcp_num);
      printf
	("AAAAAAAAAAAAAAAAtcp=%llu,http=%llu,trunck=%llu,unzip=%llu,mwm=%llu,pkt_process=%llu,find_con=%llu,find_head=%llu,find_cache=%llu,dotcp = %llu,write_log = %llu,send_msg = %llu\n",
	 delt1, delt2, delt3, delt4, delt5, delt6, delt7, delt8, delt9,
	 delt10, delt11, delt12);
      printf
	("num_conn: %lu, req_packet:%lu,resp_packet:%lu,req_sdu:%lu,resp_sdu:%lu,req:%lu,resp:%lu, other: %lu\n",
	 num_tcp_conn, num_http_req_pkt_recv, num_http_resp_pkt_recv,
	 num_http_req_sdu_data, num_http_resp_sdu_data, num_http_req_data,
	 num_http_resp_data, num_http_other_data);
      if (cur_time - last_time > 30 || send_buf->size () > 1000000)
	{
	  sem_wait (&send_buf_sem);
	  send_buf_last = send_buf;
	  if ((send_buf_index++) % 2 == 0)
	    {
	      send_buf = send_buf_b;
	    }
	  else
	    {
	      send_buf = send_buf_a;

	    }
	  sem_post (&send_buf_sem);
	  last_time = cur_time;

	  vector < stru_ud_log >::iterator iter;
	  FILE *fp = fopen ("/home/result.txt", "a+");
	  for (iter = send_buf_last->begin (); iter != send_buf_last->end ();
	       iter++)
	    {
	      info = *iter;

	      unsigned char *data = get_send_data (info);
	      //for (int i = 0; i < ud_head.Packet_Length + sizeof (ud_head);
		  // i++)
	//	{
	//	  printf ("%02x%c", data[i], (i + 1) % 16 == 0 ? '\n' : ' ');
	//	}
	  //    printf ("\n");
	      gettimeofday (&t1, NULL);
	      tcp_comm->send_msg ((char *) "127.0.0.1", 60000,
				  data,
				  ud_head.Packet_Length + sizeof (ud_head));
#if 0
	      unsigned int sip = 0, dip = 0;
	      memcpy (&sip, info.SrcIp, info.SourceIP_Length);
	      memcpy (&dip, info.DestIp, info.DestinationIP_Length);
	      bzero (str1, sizeof (str1));
	      bzero (str2, sizeof (str2));
	      fprintf (fp, "%u\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n",
		       info.GatherTime, ip2str (sip, str1), ip2str (dip,
								    str2),
		       info.SrcPort, info.DestPort, info.DomainName, info.Url,
		       info.keyword);
	      gettimeofday (&t2, NULL);
	      delt12 +=
		(t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
	      printf ("tiiiiiiiiiiiiiiiiiiiiiiime=%u\n",
		      (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec -
							   t1.tv_usec));
#endif
		  if(info.SrcIp != NULL)
			{
			free(info.SrcIp);
			info.SrcIp = NULL;
			}
			if(info.DestIp != NULL)
			{
				free(info.DestIp);
				info.DestIp = NULL;
			}
			if(info.DomainName != NULL)
			{
				free(info.DomainName);
				info.DomainName = NULL;
			}
			if(info.Title != NULL)
			{
				free(info.Title);
				info.Title = NULL;
			}
			if(info.Content != NULL)
			{
				free(info.Content);
				info.Content = NULL;
			}
			if(info.Url != NULL)
			{
				free(info.Url);
				info.Url = NULL;
			}
	if (info.Attachmentfile_Num != 0)
    {
      for (int m = 0; m < info.Attachmentfile_Num; m++)
	{
	  free(info.attach_content_t[m].AttachmentfileName);
		info.attach_content_t[m].AttachmentfileName = NULL;
	}
    }

		
			if(info.attach_content_t != NULL)
			{
				free(info.attach_content_t);
				info.attach_content_t = NULL;
			}

			if(info.keyword != NULL)
			{
				free(info.keyword);
				info.keyword = NULL;
			}
	      free(data);
	    }
	  fclose (fp);
	  send_buf_last->clear ();
	}

      printf ("send_buf.size = %d\n", send_buf->size ());
      printf ("11111111111111111, %d\n", map_result.size ());
      MapMatchRslt::iterator ptr = map_result.begin ();
      stru_match_rslt & t = ptr->second;
      for (; ptr != map_result.end (); ptr++)
	{
	  stru_match_rslt temp_rslt = ptr->second;
	  //printf ("url+host = <%s>, bingo_policy = %u, bingo_cache = %u\n",
	  //  (ptr->first).c_str (), temp_rslt.bingo_policy,
	  // temp_rslt.bingo_cache);
	}
      continue;
    }
}

void
cls_pkt_processor::packet_processer (unsigned char *arg,
				     const struct pcap_pkthdr *ph,
				     const unsigned char *packet)
{
  unsigned int caplen = ph->caplen;
  /*
     if (caplen < 54)
     return;
   */
  LLHeadStru struLLHead;
  L3HeadStru struL3Head;
  UDPHeadStru struUDPHead;
  TCPHeadStru struTCPHead;
  L4HeadUnion unionL4Head;
  unsigned char *pContent;
  unsigned int ll_head_len;
  unsigned int ip_head_len, iplen;
  unsigned int tcp_head_len;
  unsigned int content_len;

  struct timeval t1;
  struct timeval t2;
  gettimeofday (&t1, NULL);
  struLLHead = *(LLHeadStru *) packet;
  struLLHead.protocol = ntohs (struLLHead.protocol);
  cap_pkt_cnt++;
#ifdef __PRINT_LOG
  printf
    ("\n\npacket_processer: recv (((((((%lu)))))) packet, caplen = %d\n",
     cap_pkt_cnt, caplen);
#endif

  pContent = NULL;

  if (struLLHead.protocol == IP_PROTO)
    {
      ll_head_len = SIZE_BASE_LL_HEAD;
      if (caplen < ll_head_len)
	{
	  return;
	}
      struLLHead.vlan_id = -1;
    }
  else
    {
      return;
    }

  unsigned char *pPacket_begin = NULL;
  pPacket_begin = (unsigned char *) packet;

  struL3Head = *(L3HeadStru *) (pPacket_begin + ll_head_len);

  // only the TCP packet will be processed
  if (struL3Head.protocol != TCP_PROTO)
    {
      return;
    }

  struL3Head.source_addr = ntohl (struL3Head.source_addr);
  struL3Head.dest_addr = ntohl (struL3Head.dest_addr);
  struL3Head.total_len = ntohs (struL3Head.total_len);
  ip_head_len = (struL3Head.version & 0x0f) * 4;

  iplen = (struL3Head.total_len > caplen) ? caplen : struL3Head.total_len;
  if (ip_head_len > iplen)
    {
      ip_head_len = 20;		// minimum len for ip header in case of SERIOUS ABNORMALTY
    }

  struTCPHead = *(TCPHeadStru *) (pPacket_begin + ll_head_len + ip_head_len);
  struTCPHead.source_port = ntohs (struTCPHead.source_port);
  struTCPHead.dest_port = ntohs (struTCPHead.dest_port);
  struTCPHead.seq_num = ntohl (struTCPHead.seq_num);
  struTCPHead.ack_num = ntohl (struTCPHead.ack_num);
  unionL4Head.TCPHead = struTCPHead;
  tcp_head_len = ((struTCPHead.header_len & 0xf0) >> 4) * 4;
  if ((tcp_head_len + ip_head_len) > iplen)
    {
      tcp_head_len = (iplen - ip_head_len < 0) ? 0 : iplen - ip_head_len;
    }
  pContent =
    /*(char *) */
    (pPacket_begin + ll_head_len + ip_head_len + tcp_head_len);
  content_len = iplen - ip_head_len - tcp_head_len;

#if 0
  // deal with the head sector according the protocol of 3rd layer
  switch (struL3Head.protocol)
    {
    case TCP_PROTO:
      struTCPHead =
	*(TCPHeadStru *) (pPacket_begin + ll_head_len + ip_head_len);
      struTCPHead.source_port = ntohs (struTCPHead.source_port);
      struTCPHead.dest_port = ntohs (struTCPHead.dest_port);
      struTCPHead.seq_num = ntohl (struTCPHead.seq_num);
      struTCPHead.ack_num = ntohl (struTCPHead.ack_num);
      unionL4Head.TCPHead = struTCPHead;
      tcp_head_len = ((struTCPHead.header_len & 0xf0) >> 4) * 4;
      if ((tcp_head_len + ip_head_len) > iplen)
	{
	  tcp_head_len = (iplen - ip_head_len < 0) ? 0 : iplen - ip_head_len;
	}
      pContent =
	/*(char *) */
	(pPacket_begin + ll_head_len + ip_head_len + tcp_head_len);
      content_len = iplen - ip_head_len - tcp_head_len;

      break;
    case UDP_PROTO:
      struUDPHead =
	*(UDPHeadStru *) (pPacket_begin + ll_head_len + ip_head_len);
      struUDPHead.source_port = ntohs (struUDPHead.source_port);
      struUDPHead.dest_port = ntohs (struUDPHead.dest_port);
      unionL4Head.UDPHead = struUDPHead;
      content_len = iplen - ip_head_len - SIZE_UDP_HEAD;
      if (content_len < 0)
	{
	  content_len = 0;
	  pContent =
	    /*(char *) */ (pPacket_begin + ll_head_len + ip_head_len);
	}
      else
	pContent =
	  /*(char *) */
	  (pPacket_begin + ll_head_len + ip_head_len + SIZE_UDP_HEAD);
      if (caplen < ll_head_len + ip_head_len + SIZE_UDP_HEAD)
	{
	  return;
	}
      break;

    default:
      memset (&unionL4Head, 0, sizeof (L4HeadUnion));
      pContent = /*(char *) */ (pPacket_begin + ll_head_len + ip_head_len);
      content_len = iplen - ip_head_len;
    }
#endif

  if (pContent == NULL)
    return;

  //  END OF switch (struL3Head.protocol)
  if (content_len < 0)
    content_len = 0;

  unsigned short sport = 0, dport = 0;

  sport = unionL4Head.TCPHead.source_port;
  dport = unionL4Head.TCPHead.dest_port;

  if (sport == 22 || dport == 22)
    {
      return;
    }


#ifdef __PRINT_LOG
  unsigned int sip = struL3Head.source_addr;
  unsigned int dip = struL3Head.dest_addr;

  char str_sip[16], str_dip[16];
  bzero (str_sip, sizeof (str_sip));
  bzero (str_dip, sizeof (str_dip));

  struct in_addr addr;
  addr.s_addr = htonl (sip);
  strcpy (str_sip, inet_ntoa (addr));
  addr.s_addr = htonl (dip);
  strcpy (str_dip, inet_ntoa (addr));
  printf
    ("packet_processer: sip = %s, sport = %d, dip = %s, dport = %d, caplen = %d, len = %d, content_len = %d\n",
     str_sip, (int) sport, str_dip, (int) dport, ph->caplen, ph->len,
     content_len);
#endif


  if (content_len == 0
      && !(((struTCPHead.flags & 0x4) == 0x4)
	   || ((struTCPHead.flags & 0x1) == 0x1)))
//  if (content_len == 0 && (struL3Head.flag&0x4)!=0x4)
    //if (content_len ==0)
    {
#ifdef __PRINT_LOG
      printf ("packet_processer: content_len == 0, return!\n");
#endif
      //return;
    }
  else
    {
#ifdef __PRINT_LOG
      printf
	("packet_processer: content_len = %d, addr_pContent = %p, addr_packet = %p\n",
	 content_len, pContent, packet);
#endif
    }
#if 0
  if ((struTCPHead.flags & 0x4) == 0x4)
    printf ("RRRRRRRRRRRRRRRRRRRRRRR\n");

  if ((struTCPHead.flags & 0x1) == 0x1)
    printf ("FFFFFFFFFFFFFFFFFFFFFF\n");
#endif
  gettimeofday (&t2, NULL);
  delt6 += (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
  gettimeofday (&t1, NULL);

	printf("content_len = %d\n", content_len);

  DoTCPPacketProcess (&struLLHead,
		      &struL3Head,
		      &struTCPHead,
		      struL3Head.source_addr,
		      struTCPHead.source_port,
		      struL3Head.dest_addr,
		      struTCPHead.dest_port, pContent, content_len);
  gettimeofday (&t2, NULL);
  delt10 += (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
}

int
cls_pkt_processor::DoTCPPacketProcess (const LLHeadStru * pStruLLHead,
				       const L3HeadStru * pStruL3Head,
				       const TCPHeadStru * pStruTCPHead,
				       unsigned int sip,
				       unsigned short sport,
				       unsigned int dip,
				       unsigned short dport,
				       const unsigned char *pContent,
				       const unsigned int content_len)
{
	if(content_len <= 0)
		return 0;
  // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaa
  //return 0;
  if ((sip == 2102946823|| dip == 2102946823) && (pStruTCPHead->flags & TCP_FLAG_RST) != TCP_FLAG_RST)
    {
printf("RSTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT\n");
do_action_by_action (PKT_RST,
			       pStruL3Head,
			       pStruTCPHead,
			       TCP_PROTO,
			       sip, dip, sport, dport,NULL);
		return 0;
	}
return 0;
  char keyword[128];
  if (unlikely (udp_comm->get_EU_flag ()))
    //if (udp_comm->get_EU_flag())
    {
      // if the house_id changed, reload from db_table
      printf
	("DoTCPPacketProcess: EU_common info update, call ClsDBOperation.get_EU_CommInfo() to reload......\n");
	//		   TCP_PROTO, sip, dip, sport, dport, NULL);
  //  }
      ClsDBOperation.get_EU_CommInfo (house_id);
    }

  if (unlikely (udp_comm->get_House_bind_flag ()))
    //if (udp_comm->get_House_bind_flag())
    {
    }

  if (unlikely (udp_comm->get_ISMS_policy_flag ()))
    //if (udp_comm->get_ISMS_policy_flag())
    {
      // if the ISMS policy changed, reload from db_table
      printf
	("DoTCPPacketProcess: ISMS policy info update, call load_ISMS_policies() to reload......\n");
      load_ISMS_policies ();
      ISMS_ply_upd_time = time (0);
    }


  unsigned char *sdu_data = NULL;
  unsigned int sdu_len = 0;
  enum TCPDirection tcp_dir = DIR_NONE;
  int dir = 0;

  TCPsessionID tcp_id = {
    TCP_PROTO, sip, dip, sport, dport
  };

  // http_head对当前报文进行http解析的结果
  stru_http_header http_head;
  bzero (&http_head, sizeof (http_head));
  struct timeval t1;
  struct timeval t2;
  gettimeofday (&t1, NULL);
  ClsHTTPUrlCache.get_http_req_head (pContent, content_len, &http_head);
  gettimeofday (&t2, NULL);
  delt8 += (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
  if (http_head.method == 1 || http_head.method == 2)
    {
      num_http_req_pkt_recv++;
      //printf ("+++++++++++++++++++++ (((((((%lu)))))) packet is a request(%lu), \n", cap_pkt_cnt, num_http_req_pkt_recv);
    }
  else if (http_head.method == 3)
    {
      num_http_resp_pkt_recv++;
      //printf ("+++++++++++++++++++++ (((((((%lu)))))) packet is a response(%lu) \n", cap_pkt_cnt, num_http_resp_pkt_recv);
    }


#ifdef __PRINT_LOG
  printf
    ("DoTCPPacketProcess: (3) http_head.method = %d, url = %s, host = %s\n",
     http_head.method, http_head.url, http_head.host);
#endif

  // 此标记控制是否进行host/ip/port/proto等策略的匹配，在以下情况下会置位：
  // （1）连接的第一个报文到来时，因为一条连接上的信息不会变化，第一个报文的规则匹配结果会被保存在连接中
  // （2）一条没有被任何策略verdict的连接，但ISMS策略发生了变化，这时，一个连接虽然此前未命中任何协议特征
  //      策略的匹配，但策略变化后有可能命中，因此要重新匹配
  // （3）对于已经被某一策略verdict的连接，若为RST，会在前面就被RST。若为LOG动作，则生成日志。若ISMS策略
  //      发生变化，这里为了简化处理，暂不进行处理
  char flg_new_conn = 0;

  // 当前报文是否命中了某些策略的标记
  char bingo_rule = 0;

  gettimeofday (&t1, NULL);
  stru_hash_node *cur_node =
    ClsCONNHashCache.do_conn_hash_cache (conn_hash, tcp_id);
  gettimeofday (&t2, NULL);
  delt7 += (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
  stru_conn_node *cur_conn = NULL;
  if (unlikely (cur_node == NULL))
    //if (cur_node == NULL)
    {
      num_tcp_conn++;
      // 新连接，直接插入conn_hash，连接的do_match_time用来与ISMS策略的变化时间进行比较。若do_match_time
      // 小于ISMS策略的update_time，说明策略发生了变化，需要重新匹配
      flg_new_conn = 1;
     sem_wait(&conn_hash_sem);
      cur_node =
	ClsCONNHashCache.insert_new_conn (conn_hash, tcp_id, http_head);
	sem_post(&conn_hash_sem);
      cur_conn = cur_node->conn_node;
      cur_conn->do_match_time = time (0);

#ifdef __PRINT_LOG
      printf ("DoTCPPacketProcess: (4) a new conn, insert_into conn_hash\n");
#endif
      // 如果新连接上的第一个报文不是http请求报文，或者虽然是http请求，但从url中直接判断出其请求的资源为非TEXT
      // 类型，则置连接的action为RETURN，当后续连接上有http请求报文到来时，会更改action为DEAL，以便进入后续处理。
      // 一个http请求，若从url中无法确定其content-type为非TEXT类型，则默认为TEXT类型，以避免漏数据
      if (http_head.method == 0 || http_head.method == 3 || http_head.content_type == 0)	// (1)
	{
	  cur_conn->action = PKT_RET;
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (4) new conn, http_method = %d, cont_type = %d, set action = PKT_RET\n",
	     http_head.method, http_head.content_type);
#endif
	}
    }
  else
    {
	cur_node->time_stamp = time(NULL);
#ifdef __PRINT_LOG
      printf ("DoTCPPacketProcess: (4) old conn.................\n");
#endif
      cur_conn = cur_node->conn_node;
      if (cur_conn->verdict_flag == 1 && cur_conn->action == PKT_RST && (pStruTCPHead->flags & TCP_FLAG_RST) != TCP_FLAG_RST)
	{
	  // 一个被某一策略verdict过的连接，直接取出连接上的action处理，然后返回
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (4) old conn, verdict_flag == 1, do_action_by_action = %d, then return!\n",
	     cur_conn->action);
#endif
	  do_action_by_action (cur_conn->action,
			       pStruL3Head,
			       pStruTCPHead,
			       TCP_PROTO,
			       sip, dip, sport, dport,
			       (unsigned char *) (cur_conn->host));
	  return 0;
	}
      else if (unlikely (cur_conn->do_match_time < ISMS_ply_upd_time))
	//else if (cur_conn->do_match_time < ISMS_ply_upd_time)
	{
	  // 未被任何策略verdict的老连接，若ISMS策略发生了变化，置flg_new_conn标记，清空策略位图，更新do_match_timer，
	  // 重新进行host/ip/port/proto等协议策略的匹配
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (4) old conn, no verdict but policy changed, clear BMap, set action = PKT_DEAL\n",
	     cur_conn->action);
#endif
	  flg_new_conn = 1;
	  cur_conn->ply_BMap.clear ();
	  cur_conn->action = PKT_DEAL;
	  cur_conn->do_match_time = time (0);
	}

      if (http_head.url[0] != '\0')
	strncpy (cur_conn->url, http_head.url, sizeof (http_head.url));
    }

  // BBBBBBBBBBBBBBBBBBBBBBBBBBBB
  //return 0;
  if (flg_new_conn && !map_sip_rule.empty ())
    {
      if (!map_sip_rule.empty ())
	{
	  MapIPRuleInfo::iterator it = map_sip_rule.find (sip);
	  if (it != map_sip_rule.end ())
	    {
	      bingo_rule = 1;
	      ListRuleInfo & rule_list = it->second;
	      ClsCONNHashCache.set_conn_BMap_by_rulelist (cur_conn,
							  rule_list);

#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (5) 11111 match some sip rule, set BMap...........\n");
#endif
	    }
	}

      if (!map_dip_rule.empty ())
	{
	  MapIPRuleInfo::iterator it = map_dip_rule.find (dip);
	  if (it != map_dip_rule.end ())
	    {
	      bingo_rule = 1;
	      ListRuleInfo & rule_list = it->second;
	      ClsCONNHashCache.set_conn_BMap_by_rulelist (cur_conn,
							  rule_list);
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (5) 22222 match some dip rule, set BMap...........\n");
#endif
	    }
	}

      if (!map_sport_rule.empty ())
	{
	  MapPortRuleInfo::iterator it = map_sport_rule.find (sport);
	  if (it != map_sport_rule.end ())
	    {
	      bingo_rule = 1;
	      ListRuleInfo & rule_list = it->second;
	      ClsCONNHashCache.set_conn_BMap_by_rulelist (cur_conn,
							  rule_list);
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (5) 33333 match some sport rule, set BMap...........\n");
#endif
	    }
	}

      if (!map_dport_rule.empty ())
	{
	  MapPortRuleInfo::iterator it = map_dport_rule.find (dport);
	  if (it != map_dport_rule.end ())
	    {
	      bingo_rule = 1;
	      ListRuleInfo & rule_list = it->second;
	      ClsCONNHashCache.set_conn_BMap_by_rulelist (cur_conn,
							  rule_list);
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (5) 44444 match some dport rule, set BMap...........\n");
#endif
	    }
	}
    }


  if (!map_site_rule.empty ())
    {
      if (((http_head.method == 1) || (http_head.method == 2)))
	{
	  if (http_head.host[0] != '\0')
	    {
	      string string_host (http_head.host);
	      MapHostRuleInfo::iterator it = map_site_rule.find (string_host);
	      if (it != map_site_rule.end ())
		{
		  bingo_rule = 1;
		  ListRuleInfo & rule_list = it->second;
		  ClsCONNHashCache.set_conn_BMap_by_rulelist (cur_conn,
							      rule_list);
#ifdef __PRINT_LOG
		  printf
		    ("DoTCPPacketProcess: (5) 55555 match some site rule, set BMap...........\n");
#endif
		}
	    }

	  if (http_head.url[0] != '\0')
	    {
	      string string_url (http_head.url);
	      MapUrlRuleInfo::iterator it = map_url_rule.find (string_url);
	      if (it != map_url_rule.end ())
		{
		  bingo_rule = 1;
		  ListRuleInfo & rule_list = it->second;
		  ClsCONNHashCache.set_conn_BMap_by_rulelist (cur_conn,
							      rule_list);
#ifdef __PRINT_LOG
		  printf
		    ("DoTCPPacketProcess: (5) 66666 match some host rule, set BMap...........\n");
#endif
		}
	    }
	}
    }


  // 若这里就有规则命中，看是否完整命中了某个策略，若是，其优先级一定高于带有关键字的策略，
  // 直接根据策略的定义进行相应的处理，并更新连接的action及verdict_flag标记
  if (bingo_rule  && (pStruTCPHead->flags & TCP_FLAG_RST) != TCP_FLAG_RST)
    {
      int ply_idx =
	ClsCONNHashCache.check_BMap_by_conn (cur_conn, vector_policy, keyword,
					     sizeof (keyword));
#ifdef __PRINT_LOG
      printf
	("DoTCPPacketProcess: (5) bingo some rule, check_BMap_by_conn return idx: %d............\n",
	 ply_idx);
#endif
      if (ply_idx != -1)
	{
	  char flag_rst = do_action_by_policy (vector_policy[ply_idx],
					       pStruL3Head,
					       pStruTCPHead,
					       TCP_PROTO, sip, dip, sport,
					       dport,
					       cur_conn->host,
					       cur_conn->url,
					       keyword);
	  cur_conn->verdict_flag = 1;

#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (5) do action according the policy: %d, set verdict_flag, cur_conn->action = %d\n",
	     ply_idx, cur_conn->action);
#endif

	  // 若是阻断策略，则做完阻断动作后直接返回即可,这里没有返回，统一放到了后面对conn的action判断处进行返回
	  if (flag_rst)
	    {
	      cur_conn->action = PKT_RST;
	    }
	}
    }


  // step-1: find hash to get the having-been-determined status of the tcp connection
  // 查找连接表中是否已经存在相应连接信息,可能存在如下几种情况
  // (1) 一条新连接,但当前报文不是HTTP REQ,意味着报文丢失,直接将此连接的后续报文action置为return,不做处理而是直接返回
  //     当这条连接上再收到新的HTTP REQ时,会将action置为deal,以便处理同一连接上多个HTTP REQ的情况
  // (2) 一条新连接,当前报文是HTTP REQ,且明确从URL中判定请求资源为非TEXT类型,则直接将此连接的后续报文action置为return
  // (3) 一条新连接,当前报文是HTTP REQ,但URL尚未结束, 则不将其加入连接表,以便进入后面的tcp重组机制
  // (4) 一条新连接,当前报文是HTTP REQ,但不明确请求资源为非TEXT类型,则不将其加入连接表,以便进入后面的tcp重组机制
  //     对这种连接,若当前报文中可以获得url和host,则在进入tcp重组前还会进行一次cache的查找,若找到,则可以直接确定结果
  // (5) 是已存在连接,当前报文不是HTTP_REQ或HTTP_RESP,则根据当前连接表中的action进行处理
  // (6) 是已存在连接,当前报文是HTTP RESP,且找到content-type为非TEXT类型,则更新action为return
  // (7) 是已存在连接,当前报文是HTTP REQ,且确定请求资源为非TEXT类型,则更新action为return
  // (8) 是已存在连接,当前报文是HTTP REQ,但不明确请求资源为非TEXT类型,则更新action为deal,以便进入后续的tcp重组
  // (9) 是已存在连接,当前报文是HTTP REQ,但URL尚未结束,则更新action为deal,以便进入后续的tcp重组
  // (10) 是已存在连接,当前报文是HTTP RESP,且找到content-type为TEXT类型,则更新action为deal
  // (11) 是已存在连接,当前报文是HTTP RESP,但无法确定content-type,则更新action为deal
  // 补充:
  //    对于url不完整或无法准确判定为TEXT类型的HTTP REQ或HTTP RESP,将其对应的http_head.content_typeZH设置为1
  stru_conn_node *ret_conn = cur_conn;


  int doTcpRet = 0;
  gettimeofday (&t1, NULL);
  doTcpRet =
    ClsTCPReassemble.do_tcp_reassemble (cur_node, sip, dip, sport, dport,
					&dir, (TCPHeadStru *) pStruTCPHead,
					pContent, content_len, &sdu_len,
					&sdu_data);
  gettimeofday (&t2, NULL);
  delt1 += (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);


  // 前面已经将新连接插入conn_hash，因此这里ret_conn==NULL永远不会成立
  if (unlikely (ret_conn != NULL))
    {
      // 对于从http请求的url中可以直接判断为非TEXT类型的数据，不需要加入http_url_cache中，因为一个
      // http请求到来时一定要先解析url才能做http_cache的查找，但只要找到url自然就能确定其为非TEXT类型
      if (http_head.method == 1 || http_head.method == 2)
	{
	  if (http_head.content_type == 1)	// (8)(9)
	    {
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (6) http_request with text type, set action = deal\n");
#endif
	      ret_conn->action = PKT_DEAL;
	    }
	  else			// (7)
	    {
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (6) http_request with not-text type, set action = return\n");
#endif
	      ret_conn->action = PKT_RET;
	    }
	}

      // 对于从http回应中判断为非TEXT类型的数据，应该加入http_url_cache中，以便在后续有相同的请求到来时
      // 可以直接从cache中命中，尽早识别出其非TEXT类型而忽略
      // 对于text类型的，则要解析出其内容，进行关键字匹配后再加入http_url_cache中
      // 当ISMS策略发生变化时，对于http_url_cache中的非TEXT类型条目，不需进行处理
      // 对于TEXT类型的条目，则要清空其对应的策略命中信息，下一次取出条目内容重新
      // 进行关键字策略的匹配
      if (http_head.method == 3)
	{
	  // http resp，从连接上取出最新的url和host给当前报文
	  memcpy (http_head.url, ret_conn->url, sizeof (http_head.url));
	  memcpy (http_head.host, ret_conn->host, sizeof (http_head.host));
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (6) http_response: get from conn, url = %s, host = %s\n",
	     http_head.url, http_head.host);
#endif
	  if (http_head.content_type == 1)	// (10)(11)
	    {
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (6) http_response with text type, set action = PKT_DEAL\n");
#endif
	      ret_conn->action = PKT_DEAL;
	    }
	  else if (ret_conn->action != PKT_RET)	// (6)
	    {
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (6) http_response with not-text type, set action = PKT_RET\n");
#endif
	      ret_conn->action = PKT_RET;
	      ClsHTTPUrlCache.insert_not_text_to_cache (http_head.url,
							http_head.host);
	    }
	}

      switch (ret_conn->action)
	{
	case PKT_RET:
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (6) find conn_hash bingo 000000 PKT_RET, return\n");
#endif
	  return 0;
	  break;
	case PKT_RST:
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (6) find conn_hash bingo 111111 PKT_RST, do reset and return\n");
#endif
	  return 0;
	  break;
	case PKT_DEAL:
	default:
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (6) find conn_hash bingo 222222 PKT_DEAL, go on processing\n");
#endif
	  break;
	}
    }

  // CCCCCCCCCCCCCCCCCC
  //return 0;



  // step-2: 对于url和host都能完整获得的报文,查找cache,看是否能够命中?
  // 若命中,则按照cache命中条目中保存的结果进行处理
  // 若不能命中,则进行tcp重组等后续处理
  // 能够运行到这里的报文一定是以下情况中的一种:
  //   (2-1) 不完整的http req或http resp  -------------------对应上面的(3)(9)
  //   (2-2) 不能明确判定为非TEXT类型的http req或http resp -----对应上面的(4)(8)(11)
  //   (2-3) 明确判定为TEXT类型的http resp --------------------对应上面的(10)
  // 通过这一步,可以将前面一些url和host都完整,但无法判定是否text类型的http req或http resp进行
  // cache查找,若相应资源此前已经做过识别,那么在此处就可以过滤掉了.
#ifdef __PRINT_LOG
  printf
    ("DoTCPPacketProcess: (7) http_head: url = (%s), host = (%s), do_http_cache.......\n",
     http_head.url, http_head.host);
#endif

  if ((http_head.method == 1 || http_head.method == 2)
      && http_head.url[0] != '\0' && http_head.host[0] != '\0')
    {
      stru_cache_http cache_item;
      bzero (&cache_item, sizeof (cache_item));

      // get the HTTP REQUEST head and search cache
      gettimeofday (&t1, NULL);
      int ret_bingo_cache =
	ClsHTTPUrlCache.do_http_cache (http_head, &cache_item);
      gettimeofday (&t2, NULL);
      delt9 += (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
      // 返回值为0,表示cache未命中
      // 返回值为1,表示命中一个非TEXT类型的表项,将相应连接信息加入conn_hash,action=return,然后返回
      // 返回值为2,表示命中一个TEXT类型的表项,但此TEXT内容未违反安全策略,将连接信息加入conn_hash,action=return,然后返回
      // 返回值为3,表示命中一个TEXT类型的表项,且违反了安全策略但未违反过滤策略,将连接信息加入conn_hash,action=return,
      //          然后生成监测日志,并取出命中条目中的HTTP TEXT写入文件,然后返回
      // 返回值为4,表示命中一个TEXT类型的表项,且违反了过滤策略,若为并接模式,先进行RST阻断连接,将连接信息加入conn_hash,
      //          action=reset, 然后生成过滤日志,并取出命中条目中的HTTP TEXT写入文件,然后返回
      switch (ret_bingo_cache)
	{
	case 0:
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (7), do_http_cache, bingo no cache_item, go on....\n");
#endif
	  break;
	case 1:
	  cur_conn->action = PKT_RET;
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (7), do_http_cache, bingo a not-text item, set cur_conn->action = PKT_RET and return!\n");
#endif
	  return 0;
	  break;
	case 2:
	  cur_conn->action = PKT_RET;
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (7), do_http_cache, bingo a text item with no rules bingo, set cur_conn->action = PKT_RET and return!\n");
#endif
	  return 0;
	  break;
	case 3:
	  update_map_rslt_info (http_head.host, http_head.url, 0);
	  cur_conn->action = PKT_RET;
	  // do_action_by_cache_item();
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (7), do_http_cache: bingo a text item with log rules, set cur_conn->action = PKT_RET  and return!\n");
#endif

	  return 0;
	  break;
	case 4:
	  // send reset packet
	  cur_conn->action = PKT_RST;
	  // do_action_by_cache_item();
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (7), do_http_cache: bingo text item with filter rules, set cur_conn->action = PKT_RST and return!\n");
#endif
	  return 0;
	  break;
	default:
	  break;
	}
    }

  // DDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
  //return 0;



#ifdef __PRINT_LOG
  printf ("DoTCPPacketProcess: (8), do_tcp_reassemble......\n");
#endif
//struct timeval t1;
// struct timeval t2; 
  if ((doTcpRet & 0x1) != TCP_SEG_RECVED)
    {
#ifdef __PRINT_LOG
      printf
	("DoTCPPacketProcess: (8) do_tcp_reassemble return not TCP_SEG_RECVED, return 0\n");
#endif
      return 0;
    }
  tcp_num++;

  // TCP重组返回一个SDU,从此刻开始,以后的所有处理都是针对这个SDU的,而不是针对当前packet的
#ifdef __PRINT_LOG
  printf
    ("DoHttpParserPlugin: process_tcp_packet_EC return TCP_SEG_RECVED, len = %d, content as follows:\n",
     sdu_len);
#endif

  int i = 0, j = 0;
#if 0
  if (cap_pkt_cnt == 8)
    {
      for (i = 0; i < sdu_len; i++)
	{
	  printf ("%02X ", sdu_data[i]);
	  j++;

	  if (j % 8 == 0)
	    printf ("  ");
	  if (j % 16 == 0)
	    printf ("\n");

	}
      printf ("\n");
    }
#endif

  // EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
  /*
     free(sdu_data);
     sdu_data = NULL;
     return 0;
   */

  // 如果TCP重组后的SDU大于此报文的大小,说明已经于其他报文重组生成了新的SDU,需要重新进行解析以获取HTTP HEAD相关信息
  // 对于那些从未被识别,又无法通过http req或http resp明确判定其请求资源类型的,一个报文中包含了完整HTTP HEAD,在最初的
  // HTTP HEAD信息获取中已经做了完整的解析,加上此条件可以减少重复处理
  // 这种报文既可能是一个新连接,也可能是一个老连接
  // (1) 对于一个新连接,因为前面没有加入conn_hash,因此这里需要再次判断其content-type,若是非TEXT则直接加入conn_hash,action为
  //     RETURN,然后查找cache,看是否已包含相应条目,若是,则返回,否则,将条目加入cache后返回.
  //     若不是非TEXT,进行cache查找,若找到,则根据cache的命中条目进行处理,若cache未命中,则进行http重组
  // (2) 对于一个老连接,因为已经在conn_hash中找到,action前面已经更新为DEAL,这里根据新得到的url再次判断其content-type,若是非TEXT
  //     则更新conn_hash的action为RETURN,若无法确定其类型,查找cache,看是否已包含相应条目,若是,则返回,否则,将条目加入cache后返回.
  //     若不是非TEXT,进行cache查找,若找到,则根据cache的命中条目进行处理,若cache未命中,则进行http重组
  if (likely (sdu_len >= content_len))
    //if (sdu_len >= content_len)
    {
      int flag_new_sdu = 0;
#ifdef __PRINT_LOG
      printf ("DoTCPPacketProcess: (9) new reassembled SDU.........\n");
#endif
      if (sdu_len > content_len)
	{
	  flag_new_sdu = 1;
	  bzero (&http_head, sizeof (http_head));
	  ClsHTTPUrlCache.get_http_req_head (sdu_data, sdu_len, &http_head);
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (9) sdu_len > content_len, re-get the http_req head\n");
#endif
	}
      else
	{
#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (9) sdu_len = content_len, no need to re-get the http head\n");
#endif
	}

      if (http_head.method == 1 || http_head.method == 2)
	{
	  num_http_req_sdu_data++;
	}
      else if (http_head.method == 3)
	{
	  num_http_resp_sdu_data++;
	}
      else
	{
	}

      // 这里要处理的数据有以下几种
      // (1) 完整的HTTP REQ, 且从URL中明确判定为非TEXT类型
      // (2) 完整的HTTP REQ, 但从URL中无法判定为非TEXT类型
      // (3) 完整的HTTP RESP, 且从content-type中明确判定为非TEXT类型
      // (4) 完整的HTTP RESP, 且从content-type中明确判定为TEXT类型
      // (5) 非HTTP REQ或HTTP RESP
      // (1)(3)两种数据,若ret_conn==NULL,则insert至conn_hash,否则更新action为RETURN,然后cache查找,
      //                未命中则insert到cache,然后返回
      // (2)(4)两种数据,先进行cache查找,若未找到,则进行conn_hash处理,
      //               若找到,则取出cache结果,根据结果作conn_hash处理. conn_hash处理如下:
      //               ---若ret_conn==NULL,且cache未命中,则insert至conn_hash,设置action为DEAL,然后进行后续的HTTP重组
      //               ---若ret_conn==NULL,且cache命中,根据cache条目结果插入conn_hash,然后返回
      //               ---若ret_conn!=NULL,且cache未命中,则更新conn_hash条目的action为DEAL,然后进行后续的HTTP重组
      //               ---若ret_conn!=NULL,且cache命中,根据cache条目结果插入hash,然后返回
      // (5)这种数据,若ret_conn==NULL,则说明连接上第一个报文不是HTTP REQ,错误数据,
      //             insert至conn_hash,设置action为RET,若ret_conn!=NULL,
      //    更新action为DEAL,然后进行后续的HTTP重组
      if (http_head.method)
	{
	  // 若为http回应，则从连接上取出url和host，正常情况下一定是在收到http请求时插入conn表项，所以必定能取到
	  if (http_head.method == 3 && ret_conn != NULL)
	    {
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (9) tcp reassembled, http resp, get url and host from cur_conn\n");
#endif
	      strncpy (http_head.url, ret_conn->url,
		       sizeof (http_head.url) - 1);
	      strncpy (http_head.host, ret_conn->host,
		       sizeof (http_head.host) - 1);
	    }

#ifdef __PRINT_LOG
	  printf
	    ("DoTCPPacketProcess: (9), tcp reassembled: host = %s, url = %s\n",
	     http_head.host, http_head.url);
#endif
	  // 如果重组后的http请求和回应仍然无法完整取出url和host，则返回，此连接action为return，直到下一个http req到来为止。
	  // 这样处理的原因是：
	  // （1）若为http请求，则重组后必定应该包含完整的url和host，否则，一定是出错了，后续继续处理可能会引起异常，因此返回
	  // （2）若为http回应，则说明http请求已经处理完了，必定能从中conn上取出url和host，如果不完整，说明前面就出错了，也应返回
	  if (http_head.url[0] == '\0' || http_head.host[0] == '\0')
	    {
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (9) tcp_reassemble get a incomplete http header, set action = PKT_RET and return\n");
#endif
			//sem_wait(&conn_hash_sem);
	      //ClsCONNHashCache.insert_not_text_to_conn(conn_hash,tcp_id, http_head, PKT_RET);
			//sem_post(&conn_hash_sem);
	      ret_conn->action = PKT_RET;
	      return 0;
	    }
	  else
	    {
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (9) tcp_reassemble get a complete http header, update url and host of cur_conn\n");
#endif
	      strncpy (cur_conn->url, http_head.url, sizeof (cur_conn->url));
	      strncpy (cur_conn->host, http_head.host,
		       sizeof (cur_conn->host));
	    }


	  // 这里有两种情况：
	  // 一个是从http请求中即判断为非TEXT数据，不需要加入http_url_cache，直接设置conn_cache状态然后返回即可。
	  // 另一个是从http回应中判断为非TEXT数据，需要加入http_url_cache，以便下一次根据请求中的url和host即可判断出其非TEXt类型
	  if (http_head.content_type == 0)	// (1)(3)
	    {
	      /*
	         if (ret_conn == NULL)
			{
			 sem_wait(&conn_hash_sem);
	         ClsCONNHashCache.insert_not_text_to_conn(conn_hash,tcp_id, http_head, PKT_RET);
			 sem_post(&conn_hash_sem);
	         }
else
	         ret_conn->action = PKT_RET;
	       */

	      if (http_head.method == 3)
		{
		  ClsHTTPUrlCache.insert_not_text_to_cache (http_head.url,
							    http_head.host);
#ifdef __PRINT_LOG
		  printf
		    ("DoTCPPacketProcess: (9) http_response with not-text type, insert to http_url_cache\n");
#endif
		}

	      ret_conn->action = PKT_RET;
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (9) tcp_reassemble http_head.content_type == 0, set cur_conn->acton = PKT_RET\n");
#endif

	      return 0;
	    }
	  else			// (2)(4)
	    {
	      if (flag_new_sdu == 1
		  && (http_head.method == 1 || http_head.method == 2))
		{
#ifdef __PRINT_LOG
		  printf
		    ("DoTCPPacketProcess: (9) tcp_reassemble http_head.content_type == 1, do_http_cache\n");
#endif
		  stru_cache_http cache_item;
		  bzero (&cache_item, sizeof (cache_item));

		  // get the HTTP REQUEST head and search cache
		  int ret_bingo_cache =
		    ClsHTTPUrlCache.do_http_cache (http_head, &cache_item);

		  ENUM_PKT_ACTION new_action = PKT_DEAL;
		  switch (ret_bingo_cache)
		    {
		    case 0:
#ifdef __PRINT_LOG
		      printf
			("DoTCPPacketProcess: (9), do_http_cache, bingo no cache_item, go on doing...\n ");
#endif
		      break;
		    case 1:
#ifdef __PRINT_LOG
		      printf
			("DoTCPPacketProcess: (9), do_http_cache: bingo a not-text item, set action == PKT_RET\n");
#endif
		      new_action = PKT_RET;
		      break;
		    case 2:
#ifdef __PRINT_LOG
		      printf
			("DoTCPPacketProcess: (9), do_http_cache: bingo a text item with no rule bingo, set action = PKT_RET!\n");
#endif
		      update_map_rslt_info (http_head.host, http_head.url, 0);
		      new_action = PKT_RET;
		      break;
		    case 3:
#ifdef __PRINT_LOG
		      printf
			("DoTCPPacketProcess: (9), do_http_cache: bingo a text item with monitor rules, set action = PKT_RET!\n");
#endif
		      new_action = PKT_RET;
		      // create monitor logs
		      break;
		    case 4:
		      // send reset packet
#ifdef __PRINT_LOG
		      printf
			("DoTCPPacketProcess: (9), do_http_cache: bingo a text item with filter rule, set action = PKT_RST!\n");
#endif
		      new_action = PKT_RST;
		      // create filter logs
		      break;
		    default:
		      break;
		    }

		  if (ret_conn == NULL)
		    {
			 sem_wait(&conn_hash_sem);
		      ClsCONNHashCache.insert_text_to_conn (conn_hash, tcp_id,
							    http_head,
							    new_action);
			sem_post(&conn_hash_sem);
#ifdef __PRINT_LOG
		      printf
			("do_http_cache over: insert text to connn, new action = %d\n",
			 new_action);
#endif
		    }
		  else
		    {
		      ret_conn->action = new_action;
#ifdef __PRINT_LOG
		      printf
			("DoTCPPacketProcess: (9) do_http_cache over: update the action = %d of the connection\n",
			 new_action);
#endif
		    }

		  if (new_action != PKT_DEAL)
		    {
#ifdef __PRINT_LOG
		      printf
			("DoTCPPacketProcess: (9) do_http_cache_over: new action != PKT_DEAL, return\n");
#endif
		      return 0;
		    }
		}
	    }
	}
      else			// (5)
	{
	  // 非http请求或响应数据，应该是请求或回应中的后续数据，此时应设置conn的action为DEAL
	  if (ret_conn == NULL)
	    {
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (9) not a http_req/http_resp SDU in a new conn, return\n");
#endif
		sem_wait(&conn_hash_sem);
	      ClsCONNHashCache.insert_not_text_to_conn (conn_hash, tcp_id,
							http_head, PKT_RET);
		sem_post(&conn_hash_sem);
	      return 0;
	    }
	  else
	    {
#ifdef __PRINT_LOG
	      printf
		("DoTCPPacketProcess: (9) not a http_req/http_resp SDU, set action = PKT_DEAL\n");
#endif
	      ret_conn->action = PKT_DEAL;
	    }
	}
    }
  else
    {
      return 0;
    }


  // FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  /*
     free(sdu_data);
     sdu_data = NULL;
     return 0;
   */


  unsigned int http_data_len = 0;
  unsigned char *http_data = NULL;
  unsigned int unzip_len = 0;
  unsigned char *unzip_buf = NULL;


  // 根据TCP重组得到的报文进行HTTP重组,传入http_head的目的是为了在http_hash_tbl中保存相应的
  // url和host,以便在返回一个HTTP RESP时能够将相应的url和host一起返回,供cache操作使用.
  //char analyse_http_req(unsigned char *data, unsigned int datalen, stru_http_req_head *header);
  stru_http_req_head temp_http_header;
  bzero (&temp_http_header, sizeof (temp_http_header));
  temp_http_header.method = (HTTP_METHOD) http_head.method;

#ifdef __PRINT_LOG
  printf
    ("DoTCPProcess: (10) go on to do_http_reassemble: temp_http_header.method = %d\n",
     temp_http_header.method);
#endif

  int http_type = 0;
  gettimeofday (&t1, NULL);
  char ret =
    ClsHTTPReassemble.do_http_reassemble (cur_node, tcp_id, sdu_len, sdu_data,
					  &temp_http_header,
					  (enum TCPDirection) dir,
					  &http_data_len, &http_data,
					  &http_type);
  gettimeofday (&t2, NULL);
  delt2 += (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
  //free(sdu_data);
  //sdu_data = NULL;

  if (doTcpRet & 0x4 == 0x4)
    {
      //ClsHTTPReassemble.free_list(&(cur_node->http_node->sdu_list_up));
      //ClsHTTPReassemble.free_list(&(cur_node->http_node->sdu_list_down));
      //free(cur_node->http_node);
    }
  if (likely (ret != 0))
    //if (ret != 0)
    {
#ifdef __PRINT_LOG
      printf
	("DoTCPProcess: (10) do_http_reassmeble return not a http req or resp, return!!!!!\n");
#endif
      return 0;
    }
  else
    {
      http_num++;
#ifdef __PRINT_LOG
      printf
	("DoTCPProcess[((((%d)))))]: (10) do_http_reassmeble return a new http req/resp, content_len(include header) = %d, go on doing!!!\n",
	 http_num, http_data_len);
      printf
	("DoTCPProcess: (10) do_http_reassmeble return a new http req/resp, content_len(include header) = %d, go on doing!!!\n",
	 http_data_len);
      printf
	("DoTCPProcess: (10) do_http_reassemble: chunk_flag = %d, gzip_flag = %d, content_type = (%s)\n",
	 temp_http_header.chunk_flag, temp_http_header.gzip_flag,
	 temp_http_header.content_type);
#endif

//printf("http_type ==================%d\n",http_type);
      if (http_type == 1)
	{
	  free (http_data);
	  http_data = NULL;
	  num_http_other_data++;
	  //printf("http_type == 1,so return;\n");
	  return 0;
	}

      if (http_type == 1 || http_type == 2)
	{
	  num_http_req_data++;
	}
      else if (http_type == 3)
	{
	  num_http_resp_data++;
	}
      else
	{
	  num_http_other_data++;
	}
    }

#if 0
  printf
    ("DoTCPProcess: (10) getted http data, addr = %p, len = %d, content is as follows:\n",
     http_data, http_data_len);
  i = 0;
  j = 0;
  for (i = 0; i < http_data_len; i++)
    {
      printf ("%02X ", http_data[i]);
      j++;
      if (j % 8 == 0)
	printf ("  ");
      if (j % 16 == 0)
	printf ("\n");
    }
  printf ("\n");
#endif

  // GGGGGGGGGGGGGGGGGGGGGGG
  /*
     free(http_data);
     http_data = NULL;
     return 0;
   */

  ret = 0;
  if (temp_http_header.chunk_flag)
    {
      int old_len = http_data_len;
      gettimeofday (&t1, NULL);
      ret = ClsHTTPReassemble.dechunk_data (http_data, &http_data_len);
      gettimeofday (&t2, NULL);
      delt3 += (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
      if (ret != 0)
	{
#ifdef __PRINT_LOG
	  printf ("chunked data, dechunk failed, free data.......\n");
#endif
	  goto LABEL_FREE_HTTP_DATA;
	}

      if (unlikely (http_data_len >= old_len))
	//if (http_data_len >= old_len)
	{
#ifdef __PRINT_LOG
	  printf ("chunked_data, dechunk length error, free data......\n");
#endif
	  goto LABEL_FREE_HTTP_DATA;
	}
#ifdef __PRINT_LOG
      printf
	("chunk_data, dechunk success, dechunk_data_len(include header) = %d\n",
	 http_data_len);
#endif
    }

  // HHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
  /*
     free(http_data);
     http_data = NULL;
     return 0;
   */

  unzip_buf = NULL;
  unzip_len = 0;
#ifdef __PRINT_LOG
  printf ("unzip_data, addr of to be unzipped buf = %p\n", http_data);
#endif

  gettimeofday (&t1, NULL);
  ret =
    ClsHTTPReassemble.unzip_data (http_data, http_data_len, &unzip_buf,
				  &unzip_len);
  gettimeofday (&t2, NULL);
  delt4 += (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
LABEL_FREE_HTTP_DATA:
  free (http_data);
  http_data = NULL;


  if (unlikely (unzip_buf == NULL || ret != 0))
    //if (unzip_buf == NULL || ret != 0)
    {
#ifdef __PRINT_LOG
      printf ("unzip data, unzip failed, free data......\n");
#endif
      goto LABEL_FREE_UNZIP_DATA;
    }

#ifdef __PRINT_LOG
  printf ("pktno: %lu, unzip data, unzip success, unzip_len = %d\n",
	  cap_pkt_cnt, unzip_len);
#endif

  // IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
  //goto LABEL_FREE_UNZIP_DATA;

  if (temp_http_header.type_text_flag)
    {
#ifdef __PRINT_LOG
      //printf ("unzip_len = %d, content = (((((%s)))))\n", unzip_len,
      //      unzip_buf);
#endif
      /*
         printf("unzip_len = %d, content = (((((%s)))))\n", unzip_len, unzip_buf);
         int i = 0, j = 0;
         for (i = 0; i < unzip_len; i++)
         {
         printf("%02X ", unzip_buf[i]);
         j++;

         if ((j % 8) == 0)
         printf(" ");
         if ((j % 16) == 0)
         printf("\n");
         }
       */


      // 这里根据得到的http内容进行关键字匹配，若匹配到某些关键字，说明命中了一些keyword类型的rule，需要
      // 更新conn上这些rule对应的策略命中结果位图，因为do_keyword_match函数不支持返回其所命中rule对应的
      // policy列表，因此这里将连接对象作为参数传入，在内部直接设置对应连接的策略命中结果位图
      gettimeofday (&t1, NULL);
      ListRuleInfo bing_list = do_keyword_match (pStruLLHead,
						 pStruL3Head,
						 pStruTCPHead,
						 sip, dip, sport, dport,
						 unzip_buf, unzip_len);
      gettimeofday (&t2, NULL);
      delt5 += (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);

      // do_keyword_match应该返回一个包含mwm命中关键字对应rule所在的policy的索引list，如果
      // 这个list不为空，则检查此连接上的策略命中位图，如果已经全命中了一些策略，则取出
      // 对应优先级最高的那个策略，按照其定义对此连接上的当前及后续处理进行处理
      if (!bing_list.empty ())
	{

	  ClsCONNHashCache.set_conn_BMap_by_rulelist (ret_conn, bing_list);
	  int ply_idx =
	    ClsCONNHashCache.check_BMap_by_conn (cur_conn, vector_policy,
						 keyword, sizeof (keyword));

	  // 这里意味着命中了某些策略中的所有rule，前面的check_map会返回所命中策略中优先级最高的那个策略，
	  // 接下来的动作以这条策略的定义为准，同时设置连接的verdict标记，然后将对应的url和host加入http
	  // 的cache中
#ifdef __PRINT_LOG
	  printf
	    ("bingo some rule, check_BMap_by_conn return idx: %d............\n",
	     ply_idx);
#endif



	  if (ply_idx != -1 && (pStruTCPHead->flags & TCP_FLAG_RST) != TCP_FLAG_RST)
	    {
#ifdef __PRINT_LOG
	      printf ("do action according the keyword policy: %d\n",
		      ply_idx);
#endif

	      char flag_rst = do_action_by_policy (vector_policy[ply_idx],
						   pStruL3Head,
						   pStruTCPHead,
						   TCP_PROTO, sip, dip, sport,
						   dport,
						   cur_conn->host,
						   cur_conn->url,
						   keyword);
	      ret_conn->verdict_flag = 1;
	      if (flag_rst)
		ret_conn->action = PKT_RST;

	      ClsHTTPUrlCache.insert_text_to_cache (vector_policy[ply_idx],
						    ret_conn->url,
						    ret_conn->host,
						    (char *) unzip_buf,
						    unzip_len);
#ifdef __PRINT_LOG
	      printf ("match keyword policy: %d, update_map_rslt \n",
		      ply_idx);
#endif

	      update_map_rslt_info (ret_conn->host, ret_conn->url, 1);
	    }
	}
      else
	{
#ifdef __PRINT_LOG
	  printf
	    ("bingo no rule, free unzip_data, insert_to_http_cache and return\n");
#endif
	  ClsHTTPUrlCache.insert_text_to_cache (ret_conn->url,
						ret_conn->host,
						(char *) unzip_buf,
						unzip_len);
	}
    }

LABEL_FREE_UNZIP_DATA:
  if (unzip_buf != NULL)
    {
      free (unzip_buf);
      unzip_buf = NULL;
    }

  return 0;

}

void
cls_pkt_processor::update_map_rslt_info (char *host, char *url, int type)
{
  string key = "";
  key += host;
  key += "/";
  key += url;


#ifdef __PRINT_LOG
  //printf("update_map_rslt_info: host: <%s>, url: <%s>, type = %u\n", host, url, type);
#endif
  MapMatchRslt::iterator ptr = map_result.find (key);
  if (ptr != map_result.end ())
    {
      if (type)
	{
	  ((ptr->second).bingo_policy)++;
#ifdef __PRINT_LOG
	  printf
	    ("update_map_rslt_info: 1111111111, host: <%s>, url: <%s>, bing_policy = %u\n",
	     host, url, (ptr->second).bingo_policy);
#endif
	}
      else
	{
	  ((ptr->second).bingo_cache)++;
#ifdef __PRINT_LOG
	  printf
	    ("update_map_rslt_info: 1111111111, host: <%s>, url: <%s>, bing_cache = %u\n",
	     host, url, (ptr->second).bingo_cache);
#endif
	}
    }
  else
    {
      stru_match_rslt temp = {
	0, 0
      };
      if (type)
	{
	  (temp.bingo_policy) = 1;
	  (temp.bingo_cache) = 0;
#ifdef __PRINT_LOG
	  printf
	    ("update_map_rslt_info: 2222222222, host: <%s>, url: <%s>, type = %u, bingo_policy = %u, bingo_cache = %u\n",
	     host, url, type, temp.bingo_policy, temp.bingo_cache);
#endif
	}
      else
	{
	  (temp.bingo_policy) = 0;
	  (temp.bingo_cache) = 1;
#ifdef __PRINT_LOG
	  printf
	    ("update_map_rslt_info: 2222222222, host: <%s>, url: <%s>, type = %u, bingo_policy = %u, bingo_cache = %u\n",
	     host, url, type, temp.bingo_policy, temp.bingo_cache);
#endif
	}

      map_result.insert (pair < string, stru_match_rslt > (key, temp));
#ifdef __PRINT_LOG
      //printf("update_map_rslt_info: 2222222222, host: <%s>, url: <%s>, type = %u\n", host, url, type);
#endif

    }
}



// end of the file

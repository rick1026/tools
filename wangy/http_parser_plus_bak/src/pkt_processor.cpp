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
#define __PRINT_LOG


cls_pkt_processor::cls_pkt_processor()
{
	//Initialize();
}

cls_pkt_processor::cls_pkt_processor(int client_id)
{
	this->client_id = client_id;
	Initialize();
}
cls_pkt_processor::~cls_pkt_processor()
{
}

char cls_pkt_processor::read_house_info()
{
}

char cls_pkt_processor::read_comm_conf_from_file()
{
    char row[256];
    FILE *fd = fopen("/var/beap_conf/IDC_port_conf.txt", "r");
    if (fd == NULL)
    {
        printf("read_comm_conf: open file /var/beap_conf/IDC_port_conf.txt error!\n");
        serv_port_policy_update = 61001 + client_id;
        client_port_ud_log = 61000;
        client_port_ud_attach = 61100;
        return 0;
    }

    bzero(row, sizeof(row));
    while(fgets(row, sizeof(row), fd) != NULL)
    {
        if (row[0] == '\n' || row[0] == '#')
            continue;

        row[strlen(row) - 1] = '\0';

        char *pos = NULL;
        if ( (pos = strstr(row, "<PORT_LISTEN_UD_LOG>")) != NULL)
        {
            client_port_ud_log = atoi(pos + strlen("<PORT_LISTEN_UD_LOG>"));
        }
        else if ( (pos = strstr(row, "<PORT_LISTEN_ATTATCH>")) != NULL)
        {
            client_port_ud_attach = atoi(pos + strlen("<PORT_LISTEN_ATTATCH>"));
        }
        else if ( (pos = strstr(row, "<PORT_POLICY_UPDATE_BEGIN>")) != NULL)
        {
            serv_port_policy_update = atoi(pos + strlen("<PORT_POLICY_UPDATE_BEGIN>")) + client_id;
        }
        else
            continue;
    }

    fclose(fd);
    return 0;
}

char cls_pkt_processor::load_ISMS_policies()
{
	if (mwm_handle != NULL)
	{
		mwmFree(mwm_handle);
		mwm_handle == NULL;
	}
	mwm_handle = mwmNew();
	if (mwm_handle == NULL)
	{
		printf("load_ISMS_policies: mwm_handle == NULL, exit!!!!!\n");
		exit(1);
	}
	else
	{
		printf("load_ISMS_policies: mwm_handle == mwmNew() success!!!!!\n");
	}

    map_site_rule.clear();
    map_url_rule.clear();
    map_proto_rule.clear();
    map_sip_rule.clear();
    map_dip_rule.clear();
    map_sport_rule.clear();
    map_dport_rule.clear();
    
    ClsDBOperation.get_ISMS_policy(house_id, vector_policy);
    size_t len = vector_policy.size();

    stru_ISMS_policy  temp_policy;
	char keyword[256];
	char keyword_gbk[512];
	char keyword_big5[512];

    printf("\n\n*******************************************************\n", len);
    printf("There are %d ISMS policies totally\n", len);
	char mwm_add_flag = 0;
	int keyword_ply_num = 0;
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

        size_t len_rule = temp_policy.vector_rule.size();
        struct stru_ISMS_policy_rule temp_rule;
        for (size_t j = 0; j < len_rule; j++)
        {
			int nocase = 1;
            stru_prule_position    coordinate = {i, j};
            temp_rule = temp_policy.vector_rule[j];
            vector_policy[i].BMap.setbit(j);
            //printf("\trule[%d].policy_index: %d\n", j, temp_rule.policy_index);
            //printf("\trule[%d].Rule_SubType: %d\n", j, temp_rule.Rule_SubType);
            switch(temp_rule.Rule_SubType)
            {
                case 1: // host rule
                    //printf("\trule[%d].Rule_Host: %s, domain rule\n", j, temp_rule.Rule_Host);
                    break;
                case 2:
                    //printf("\trule[%d].Rule_Url: %s, URL rule\n", j, temp_rule.Rule_Url);
                    break;
                case 3:
                    //printf("\trule[%d].Rule_Keyword: range = %d, %s, Keyword rule\n", j, temp_rule.Rule_KeyRange, temp_rule.Rule_Keyword);
					
					bzero(keyword, sizeof(keyword));
					bzero(keyword_gbk, sizeof(keyword_gbk));
					bzero(keyword_big5, sizeof(keyword_big5));
					memcpy(keyword, temp_rule.Rule_Keyword, sizeof(keyword));

					/*
					printf("keyword: addr = %p, len = %d, content = <%s>\n", keyword, strlen(keyword), keyword);
					printf("keyword_gbk: addr = %p, len = %d, content = <%s>\n", keyword_gbk, strlen(keyword_gbk), keyword_gbk);
					printf("keyword_big5: addr = %p, len = %d, content = <%s>\n", keyword_big5, strlen(keyword_big5), keyword_big5);
					*/

					iconv_utf8_gbk(keyword_gbk, sizeof(keyword_gbk), keyword, strlen(keyword));
					//iconv_utf8_Big5(keyword_big5, sizeof(keyword_big5), keyword, strlen(keyword));

					/*
					printf("keyword: addr = %p, len = %d, content = <%s>\n",keyword, strlen(keyword), keyword);
					printf("keyword_gbk: addr = %p, len = %d, content = <%s>\n",keyword_gbk, strlen(keyword_gbk), keyword_gbk);
					printf("keyword_big5: addr = %p, len = %d, content = <%s>\n",keyword_big5, strlen(keyword_big5), keyword_big5);
					*/

					mwmAddPatternEx(mwm_handle,
							(unsigned char*)(keyword),
							strlen(keyword),
							nocase,
							0,
							0,
							i,
							0,
							j);

					mwmAddPatternEx(mwm_handle,
							(unsigned char*)(keyword_gbk),
							strlen(keyword_gbk),
							nocase,
							0,
							0,
							i,
							0,
							j);
					/*
					mwmAddPatternEx(mwm_handle,
							(unsigned char*)(keyword_big5),
							strlen(keyword_big5),
							nocase,
							0,
							0,
							i,
							0,
							j);
					*/
					mwm_add_flag = 1;
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

            add_rule_to_map(coordinate, temp_rule);
        }
        //printf("ISMS_policy[%d].BMap: %s\n", i, vector_policy[i].BMap.getmap().c_str());
        //printf("---------------------------------------------------------\n");

    }
	if (mwm_add_flag)
		mwmPrepPatterns(mwm_handle);
    printf("*******************************************************\n", len);

    printf(">>>>>>>>>> The site rule information is as follows:\n");
    for (MapHostRuleInfo::iterator it = map_site_rule.begin(); it != map_site_rule.end(); it++)
    {
        printf("host = <%s>\n", it->first.c_str());
        ListRuleInfo  &rule_list = it->second;
        ListRuleInfo::iterator it_list = rule_list.begin();
        int i = 0;
        while(it_list != rule_list.end())
        {
            stru_prule_position coordinate = *it_list;
            it_list++;
            printf("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
                   i++, coordinate.ply_idx, coordinate.rule_idx, coordinate.ply_idx,
                   vector_policy[coordinate.ply_idx].BMap.getmap().c_str());
        }
    }
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

    printf(">>>>>>>>>> The url rule information is as follows:\n");
    for (MapUrlRuleInfo::iterator it = map_url_rule.begin(); it != map_url_rule.end(); it++)
    {
        printf("url = <%s>\n", it->first.c_str());
        ListRuleInfo  &rule_list = it->second;
        ListRuleInfo::iterator it_list = rule_list.begin();
        int i = 0;
        while(it_list != rule_list.end())
        {
            stru_prule_position coordinate = *it_list;
            it_list++;
            printf("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
                   i++, coordinate.ply_idx, coordinate.rule_idx, coordinate.ply_idx,
                   vector_policy[coordinate.ply_idx].BMap.getmap().c_str());
        }
    }
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

    printf(">>>>>>>>>> The proto rule information is as follows:\n");
    for (MapProtoRuleInfo::iterator it = map_proto_rule.begin(); it != map_proto_rule.end(); it++)
    {
        printf("proto = <%d>\n", it->first);
        ListRuleInfo  &rule_list = it->second;
        ListRuleInfo::iterator it_list = rule_list.begin();
        int i = 0;
        while(it_list != rule_list.end())
        {
            stru_prule_position coordinate = *it_list;
            it_list++;
            printf("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
                   i++, coordinate.ply_idx, coordinate.rule_idx, coordinate.ply_idx,
                   vector_policy[coordinate.ply_idx].BMap.getmap().c_str());
        }
    }
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

	printf(">>>>>>>>>> The sip rule information is as follows:\n");
    for (MapIPRuleInfo::iterator it = map_sip_rule.begin(); it != map_sip_rule.end(); it++)
    {
        printf("sip = <%lu>\n", it->first);
        ListRuleInfo  &rule_list = it->second;
        ListRuleInfo::iterator it_list = rule_list.begin();
        int i = 0;
        while(it_list != rule_list.end())
        {
            stru_prule_position coordinate = *it_list;
            it_list++;
            printf("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
                   i++, coordinate.ply_idx, coordinate.rule_idx, coordinate.ply_idx,
                   vector_policy[coordinate.ply_idx].BMap.getmap().c_str());
        }
    }
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");


    printf(">>>>>>>>>> The dip rule information is as follows:\n");
    for (MapIPRuleInfo::iterator it = map_dip_rule.begin(); it != map_dip_rule.end(); it++)
    {
        printf("dip = <%lu>\n", it->first);
        ListRuleInfo  &rule_list = it->second;
        ListRuleInfo::iterator it_list = rule_list.begin();
        int i = 0;
        while(it_list != rule_list.end())
        {
            stru_prule_position coordinate = *it_list;
            it_list++;
            printf("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
                   i++, coordinate.ply_idx, coordinate.rule_idx, coordinate.ply_idx,
                   vector_policy[coordinate.ply_idx].BMap.getmap().c_str());
        }
    }
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
    
    printf(">>>>>>>>>> The sport rule information is as follows:\n");
    for (MapPortRuleInfo::iterator it = map_sport_rule.begin(); it != map_sport_rule.end(); it++)
    {
        printf("sport = <%u>\n", it->first);
        ListRuleInfo  &rule_list = it->second;
        ListRuleInfo::iterator it_list = rule_list.begin();
        int i = 0;
        while(it_list != rule_list.end())
        {
            stru_prule_position coordinate = *it_list;
            it_list++;
            printf("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
                   i++, coordinate.ply_idx, coordinate.rule_idx, coordinate.ply_idx,
                   vector_policy[coordinate.ply_idx].BMap.getmap().c_str());
        }
    }
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
    
    printf(">>>>>>>>>> The dport rule information is as follows:\n");
    for (MapPortRuleInfo::iterator it = map_dport_rule.begin(); it != map_dport_rule.end(); it++)
    {
        printf("dport = <%u>\n", it->first);
        ListRuleInfo  &rule_list = it->second;
        ListRuleInfo::iterator it_list = rule_list.begin();
        int i = 0;
        while(it_list != rule_list.end())
        {
            stru_prule_position coordinate = *it_list;
            it_list++;
            printf("\tcoordinate[%d] = <%d, %d>, policy[%d].BMap: %s\n",
                   i++, coordinate.ply_idx, coordinate.rule_idx, coordinate.ply_idx,
                   vector_policy[coordinate.ply_idx].BMap.getmap().c_str());
        }
    }
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
}

inline void cls_pkt_processor::add_rule_to_map(stru_prule_position coordinate, stru_ISMS_policy_rule rule)
{
    if (rule.Rule_SubType == 1)// host rule
    {
        string str_host(rule.Rule_Host);
        MapHostRuleInfo::iterator pos = map_site_rule.find(str_host);
        if (pos != map_site_rule.end())
        {
            printf("\tThe host(%s) has been come up before!!!!!\n", rule.Rule_Host);
            ListRuleInfo &rule_list = pos->second;
            rule_list.push_back(coordinate);
        }
        else
        {
            printf("\tThe host(%s) is a new one!!!!!\n", rule.Rule_Host);
            ListRuleInfo rule_list;
            rule_list.clear();
            rule_list.push_back(coordinate);

            map_site_rule.insert(pair<string, ListRuleInfo>(str_host, rule_list));
        }
    }
    else if (rule.Rule_SubType == 2) // url rule
    {
        string str_url(rule.Rule_Url);
        MapUrlRuleInfo::iterator pos = map_url_rule.find(str_url);
        if (pos != map_url_rule.end())
        {
            printf("\tThe url(%s) has been come up before!!!!!\n", rule.Rule_Url);
            ListRuleInfo &rule_list = pos->second;
            rule_list.push_back(coordinate);
        }
        else
        {
            printf("\tThe url(%s) is a new one!!!!!\n", rule.Rule_Url);
            ListRuleInfo rule_list;
            rule_list.clear();
            rule_list.push_back(coordinate);

            map_url_rule.insert(pair<string, ListRuleInfo>(str_url, rule_list));
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
            MapIPRuleInfo::iterator pos = map_sip_rule.find(sip);
            if (pos != map_sip_rule.end())
            {
                printf("\tThe sip(%lu) has been come up before!!!!!\n", sip);
                ListRuleInfo &rule_list = pos->second;
                rule_list.push_back(coordinate);
            }
            else
            {
                printf("\tThe sip(%lu) is a new one!!!!!\n", sip);
                ListRuleInfo rule_list;
                rule_list.clear();
                rule_list.push_back(coordinate);

                map_sip_rule.insert(pair<unsigned long, ListRuleInfo>(sip, rule_list));
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
            MapIPRuleInfo::iterator pos = map_dip_rule.find(dip);
            if (pos != map_dip_rule.end())
            {
                printf("\tThe dip(%lu) has been come up before!!!!!\n", dip);
                ListRuleInfo &rule_list = pos->second;
                rule_list.push_back(coordinate);
            }
            else
            {
                printf("\tThe dip(%lu) is a new one!!!!!\n", dip);
                ListRuleInfo rule_list;
                rule_list.clear();
                rule_list.push_back(coordinate);

                map_dip_rule.insert(pair<unsigned long, ListRuleInfo>(dip, rule_list));
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
            MapPortRuleInfo::iterator pos = map_sport_rule.find(port);
            if (pos != map_sport_rule.end())
            {
                printf("\tThe sport(%u) hash been come up before!!!!!\n", port);
                ListRuleInfo &rule_list = pos->second;
                rule_list.push_back(coordinate);
            }
            else
            {
                printf("\tThe sport(%u) is a new one!!!!!\n", port);
                ListRuleInfo rule_list;
                rule_list.clear();
                rule_list.push_back(coordinate);

                map_sport_rule.insert(pair<unsigned int, ListRuleInfo>(port, rule_list));
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
            MapPortRuleInfo::iterator pos = map_dport_rule.find(port);
            if (pos != map_dport_rule.end())
            {
                printf("\tThe dport(%u) hash been come up before!!!!!\n", port);
                ListRuleInfo &rule_list = pos->second;
                rule_list.push_back(coordinate);
            }
            else
            {
                printf("\tThe sport(%u) is a new one!!!!!\n", port);
                ListRuleInfo rule_list;
                rule_list.clear();
                rule_list.push_back(coordinate);

                map_dport_rule.insert(pair<unsigned int, ListRuleInfo>(port, rule_list));
            }
        }
    }
    else if (rule.Rule_SubType == 8)
    {
        int proto = rule.Rule_ProtoL4;
        MapProtoRuleInfo::iterator pos = map_proto_rule.find(proto);
        if (pos != map_proto_rule.end())
        {
            printf("\tThe proto(%d) has been come up before!!!!!\n", proto);
            ListRuleInfo &rule_list = pos->second;
            rule_list.push_back(coordinate);
        }
        else
        {
            printf("\tThe proto(%d) is a new one!!!!!\n", proto);
            ListRuleInfo rule_list;
            rule_list.clear();
            rule_list.push_back(coordinate);

            map_proto_rule.insert(pair<int, ListRuleInfo>(proto, rule_list));
        }
    }
}


/*
int cls_pkt_processor::do_keyword_match(const LLHeadStru *pStruLLHead,
                         const L3HeadStru *pStruL3Head,
                         const TCPHeadStru *pStruTCPHead,
                         unsigned int sip,
                         unsigned short sport,
                         unsigned int dip,
                         unsigned short dport,
                         unsigned char *data_buf,
                         unsigned int data_len)
{
    unsigned long ret = 0;
    unsigned char search_rslt[SIZE_SEARCH_RSLT];
    bzero(search_rslt, sizeof(search_rslt));
    //printf(">>>>>>>>>>>>>>>>>>> search_rslt: sizeof = %d bytes\n", SIZE_SEARCH_RSLT);

    unsigned char temp_buf[65535];
    bzero(temp_buf, sizeof(temp_buf));

    int temp_buf_len = (data_len < 65535) ? (data_len) : (65534);

    memcpy(temp_buf, data_buf, temp_buf_len);

#ifdef __DEBUG_MWM_FIND_STRING
    //printf("content to be matched: len = %d, (((((%s)))))\n", temp_buf_len, temp_buf);
#endif

    ret = beap_mwm_search_search(mwm_handle, &search_rslt[0], (signed char*)temp_buf, temp_buf_len);
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
        if (search_rslt == 0)
            continue;

        //printf("search_rlst[%d] = %d\n", i, (int)(search_rslt[i]));

        int rule_id = i / SIZE_PER_RULE_RSLT;
        int key_id = 0;

        for (j = 0; j < KEY_NUM_PER_RULE_RSLT; j++)
        {
            key_id = ((i*8) % 128) + j;
            if ((search_rslt[i]) & (0x01 << j))
            {
                struContWarnRule *ptr_rule = (struContWarnRule*)(ptr_content_rule[rule_id]);
                struMwmSearchKey *key = (struMwmSearchKey*)(ptr_rule->ptr_key[key_id]);

                bingo_cnt++;
                bingo_cnt++;
                if (rule_id == 0 && key_id == 127)
                    bingo_cnt_key_0_127++;
                else if (rule_id == 1 && key_id == 100)
                    bingo_cnt_key_1_100++;
                else if (rule_id == 6 && key_id == 0)
                    bingo_cnt_key_6_0++;
                else
                    bingo_cnt_key_127_127++;
#ifdef __DEBUG_MWM_FIND_STRING
                printf("rule_id = %d, key_id = %d, bingo keyword: %s\n", rule_id, key_id, key->content);
                printf("rule_id = %d, key_id = %d, bingo keyword: %s\n", rule_id, key_id, key->content);
#endif
            }
            else
            {
                //printf("rule_id = %d, key_id = %d, not bingo\n", rule_id, key_id);
            }

        }

    }
    return 0;
}

*/

ListRuleInfo cls_pkt_processor::do_keyword_match(const LLHeadStru *pStruLLHead,
		const L3HeadStru *pStruL3Head,
		//const L4HeadUnion *pUnionL4Head,
		const TCPHeadStru *pStruTCPHead,
		unsigned int sip,
		unsigned short sport,
		unsigned int dip,
		unsigned short dport,
		unsigned char *data_buf,
		unsigned int data_len)
{
	ListRuleInfo  list_rule_bingo;
	list_rule_bingo.clear();

	unsigned long ret = 0;
	unsigned char search_rslt[SIZE_SEARCH_RSLT];
	bzero(search_rslt, sizeof(search_rslt));
	//printf(">>>>>>>>>>>>>>>>>>> search_rslt: sizeof = %d bytes\n", SIZE_SEARCH_RSLT);

	unsigned char temp_buf[65535];
	bzero(temp_buf, sizeof(temp_buf));

	int temp_buf_len = (data_len < 65535) ? (data_len) : (65534);
	
	memcpy(temp_buf, data_buf, temp_buf_len);

#ifdef __DEBUG_MWM_FIND_STRING
	//printf("content to be matched: len = %d, (((((%s)))))\n", temp_buf_len, temp_buf);
#endif

	ret = beap_mwm_search_search(mwm_handle, &search_rslt[0], (signed char*)temp_buf, temp_buf_len);
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
struct timeval t1;
struct timeval t2;
	for (i = 0; i < SIZE_SEARCH_RSLT; i++)
	{
		if (search_rslt == NULL)
			continue;
#if 0
		int rule_id = i >> 4; // modified on 20150807
		int key_id = 0;
		int key_id_base = ((i << 3) % 128);
	//unsigned long long temp = (unsigned long long)(search_rslt+i);
	unsigned char temp = *((unsigned char*)(search_rslt+i));
		if(temp == 0)
			continue;
#if 1
  if (temp >= 128)
    {
				key_id = key_id_base + 7;
				stru_prule_position coordinate = {rule_id, key_id};
				list_rule_bingo.push_back(coordinate);
      temp &= 0x7f;
    }
  if (temp >= 64)
    {
				key_id = key_id_base + 6;
				stru_prule_position coordinate = {rule_id, key_id};
				list_rule_bingo.push_back(coordinate);
      temp &= 0x3f;
    }
  if (temp >= 32)
    {
				key_id = key_id_base + 5;
				stru_prule_position coordinate = {rule_id, key_id};
				list_rule_bingo.push_back(coordinate);
      temp &= 0x1f;
    }
  if (temp >= 16)
    {
				key_id = key_id_base + 4;
				stru_prule_position coordinate = {rule_id, key_id};
				list_rule_bingo.push_back(coordinate);
      temp &= 0xf;
    }
  if (temp >= 8)
    {
				key_id = key_id_base + 3;
				stru_prule_position coordinate = {rule_id, key_id};
				list_rule_bingo.push_back(coordinate);
      temp &= 0x7;
    }
  if (temp >= 4)
    {
				key_id = key_id_base + 2;
				stru_prule_position coordinate = {rule_id, key_id};
				list_rule_bingo.push_back(coordinate);
      temp &= 0x3;
    }
  if (temp >= 2)
    {
				key_id = key_id_base + 1;
				stru_prule_position coordinate = {rule_id, key_id};
				list_rule_bingo.push_back(coordinate);
      temp &= 0x1;
    }
  if (temp >= 1)
    {
				key_id = key_id_base;
				stru_prule_position coordinate = {rule_id, key_id};
				list_rule_bingo.push_back(coordinate);
      temp = 0;
    }
#endif
#endif
#if 0
		//if(search_rslt[i] == 0)
		//	continue;
		//printf("search_rlst[%d] = %d\n", i, (int)(search_rslt[i]));

		//int rule_id = i / SIZE_PER_RULE_RSLT;
		int rule_id = i >> 4; // modified on 20150807
		int key_id = 0;
		
		for (j = 0; j < KEY_NUM_PER_RULE_RSLT; j++)
		{
			//key_id = ((i*8) % 128) + j;
			key_id = ((i << 3) % 128) + j;
			if ((search_rslt[i]) & (0x01 << j))
			{
				struContWarnRule *ptr_rule = (struContWarnRule*)(ptr_content_rule[rule_id]);
				struMwmSearchKey *key = (struMwmSearchKey*)(ptr_rule->ptr_key[key_id]);

				printf("rule_id = %d, key_id = %d, bingo keyword: %s\n", rule_id, key_id, key->content);
#ifdef __DEBUG_MWM_FIND_STRING
				//printf("rule_id = %d, key_id = %d, bingo keyword: %s\n", rule_id, key_id, key->content);
				//printf("rule_id = %d, key_id = %d, bingo keyword: %s\n", rule_id, key_id, key->content);
#endif
				stru_prule_position coordinate = {rule_id, key_id};
				list_rule_bingo.push_back(coordinate);
			}
			else
			{
				//printf("rule_id = %d, key_id = %d, not bingo\n", rule_id, key_id);
			}

		}
#endif

	}

	return list_rule_bingo;
}

void cls_pkt_processor::send_L3_reset(int sock,
                                    unsigned long sip,
                                    unsigned long dip,
                                    unsigned int  sport,
                                    unsigned int  dport,
                                    unsigned long seq,
                                    unsigned long next_ack_seq)
{
    L3HeadStru              *L3Head = NULL;
    TCPHeadStru             *L4Head = NULL;
    char                    buf[1500];
    char                    sp_pseudo_ip_construct[1500];
    struct pseudo_IP_header *sp_help_pseudo;

    bzero(buf, sizeof(buf));
    bzero(sp_pseudo_ip_construct, sizeof(sp_pseudo_ip_construct));

    L3Head = (L3HeadStru*)buf;
    L3Head->version = (4 << 4) | (20/4);
    L3Head->diff_serv_field = 0;
    L3Head->total_len = htons(20 + 20);
    L3Head->identification = htons(12545);
    L3Head->flag = 0;
    L3Head->TTL = 69;
    L3Head->protocol = 6;
    L3Head->header_checksum = in_cksum((unsigned short*)buf, 20);
    L3Head->source_addr = htonl(sip);
    L3Head->dest_addr = htonl(dip);
    sp_help_pseudo = (struct pseudo_IP_header*)sp_pseudo_ip_construct;

    L4Head = (TCPHeadStru*)(buf + 20);
    L4Head->header_len = 0x50;
    L4Head->flags = 0x14;
    L4Head->seq_num = htonl(seq);
    L4Head->ack_num = htonl(next_ack_seq);
    L4Head->source_port = htons(sport);
    L4Head->dest_port = htons(dport);
    L4Head->win_size = htons(0x7c00);

    sp_help_pseudo->source = htonl(sip);
    sp_help_pseudo->destination = htonl(dip);
    sp_help_pseudo->zero_byte = 0;
    sp_help_pseudo->protocol = 6;
    sp_help_pseudo->TCP_UDP_len = htons(20);

	memcpy(sp_pseudo_ip_construct + 12, L4Head, 20);
    L4Head->checksum = in_cksum((unsigned short*)sp_pseudo_ip_construct, 12 + 20);

    struct sockaddr_in sp_server;
    int                HEAD_BASE = 20;

    bzero(&sp_server, sizeof(sp_server));
    sp_server.sin_family = AF_INET;
    sp_server.sin_addr.s_addr = htonl(dip);

    int sp_status = sendto(sock, (char*)buf, HEAD_BASE + 20, 0, (struct sockaddr*)&sp_server, sizeof(struct sockaddr));
    if (sp_status == -1)
        printf("send reset packet error!!!!!\n");
    else
        printf("send reset packet: from(%u:%d) to (%u:%d)\n", sip, sport, dip, dport);

}

unsigned short cls_pkt_processor::in_cksum(unsigned short *addr, int len)
{
    register int nleft = len;
    register unsigned short *w = addr;
    register int sum = 0;
    unsigned short answer = 0;

    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer =~sum;

    return (answer);
}


char cls_pkt_processor::do_action_by_action(ENUM_PKT_ACTION action,
		                                  const L3HeadStru *pStruL3Head,
                             			  const TCPHeadStru *pStruTCPHead, 
                                          int              proto,
                                          unsigned long    sip,
                                          unsigned long    dip,
                                          unsigned int     sport,
                                          unsigned int     dport, 
                                          unsigned char    *host)
{
	int payload_len = 0;
	switch(action)
	{
	case PKT_RST:
		payload_len = pStruL3Head->total_len - 20 - (pStruTCPHead->header_len >> 4)*4;
		send_L3_reset(sock_reset, sip, dip, sport, dport, ntohl(pStruTCPHead->seq_num) + payload_len, ntohl(pStruTCPHead->ack_num));
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


char cls_pkt_processor::do_action_by_policy(stru_ISMS_policy policy,
		                                  const L3HeadStru *pStruL3Head,
                             			  const TCPHeadStru *pStruTCPHead, 
                                          int              proto,
                                          unsigned long    sip,
                                          unsigned long    dip,
                                          unsigned int     sport,
                                          unsigned int     dport, 
                                          unsigned char    *host)
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

	return policy.BlockFlag;

	if (policy.BlockFlag)
	{
		// send reset packet 
		int payload_len = pStruL3Head->total_len - 20 - (pStruTCPHead->header_len >> 4)*4;
		//send_L3_reset(sock_reset, sip, dip, sport, dport, ntohl(pStruTCPHead->seq_num) + payload_len, ntohl(pStruTCPHead->ack_num));
	}

	if (policy.LogFlag)
	{
		unsigned char *log_packet = NULL;
		int           log_packet_len = 0;
		if (policy.Type == 1)
		{
			printf("assemble_monitor_log_packet..............\n");
			log_packet_len = assemble_monitor_log_packet(&log_packet);
		}
		else if(policy.Type == 2)
		{
			printf("assemble_filter_log_packet..............\n");
			log_packet_len = assemble_filter_log_packet(&log_packet);
		}
		else
		{
		}

		if (log_packet_len > 0)
		{
			//tcp_comm->send_msg((char*)"127.0.0.1", client_port_ud_log, log_packet, log_packet_len);
			printf("free log_packet.................\n");
			free(log_packet);
		}
	}

	return policy.BlockFlag;
}

int cls_pkt_processor::assemble_monitor_log_packet(unsigned char **out_buf)
{
    unsigned char * msg_to_send_tmp = NULL;
    unsigned long buf_bytes=0;

    struct ud_header ud_header_for_monitor;
    struct monitor_log_info ud_log_info_for_monitor;
    bzero(&ud_header_for_monitor, sizeof(struct ud_header));
    bzero(&ud_log_info_for_monitor, sizeof(struct monitor_log_info));

    ud_header_for_monitor.Ver_and_Resv=0x01;
    memcpy(ud_header_for_monitor.Proto_Signature,"CUD",3);
    ud_header_for_monitor.DevID=0x02;
    memcpy(ud_header_for_monitor.DeviceSerialNo,"123",3);
    ud_header_for_monitor.Packet_Type=0x01;
    ud_header_for_monitor.Packet_Subtype=0xe0;
    memcpy(ud_header_for_monitor.Resv,"re",2);

    memcpy(ud_log_info_for_monitor.CommandID,"command",7);
    ud_log_info_for_monitor.House_ID_Length=0x05;
    ud_log_info_for_monitor.House_ID=(unsigned char *)malloc((int)(ud_log_info_for_monitor.House_ID_Length));
    memset(ud_log_info_for_monitor.House_ID,0,(int)(ud_log_info_for_monitor.House_ID_Length));
    memcpy(ud_log_info_for_monitor.House_ID,"house",5);

    ud_log_info_for_monitor.SourceIP_Length=0x04;
    ud_log_info_for_monitor.SrcIp=(unsigned char *)malloc((int)(ud_log_info_for_monitor.SourceIP_Length));
    memset(ud_log_info_for_monitor.SrcIp,0,(int)(ud_log_info_for_monitor.SourceIP_Length));
    memcpy(ud_log_info_for_monitor.SrcIp,"1234",4);

    ud_log_info_for_monitor.DestinationIP_Length=0x04;
    ud_log_info_for_monitor.DestIp=(unsigned char *)malloc((int)(ud_log_info_for_monitor.DestinationIP_Length));
    memset(ud_log_info_for_monitor.DestIp,0,(int)(ud_log_info_for_monitor.DestinationIP_Length));
    memcpy(ud_log_info_for_monitor.DestIp,"5678",4);

    ud_log_info_for_monitor.SrcPort=htons(80);
    ud_log_info_for_monitor.DestPort=htons(90);
    ud_log_info_for_monitor.DomainName_Length=htons(9);
    ud_log_info_for_monitor.DomainName=(unsigned char *)malloc((int)(ud_log_info_for_monitor.DomainName_Length));
    memset(ud_log_info_for_monitor.DomainName,0,(int)(ud_log_info_for_monitor.DomainName_Length));
    memcpy(ud_log_info_for_monitor.DomainName,"baidu.com",9);

    ud_log_info_for_monitor.ProxyType_Flag=htons(0);
    ud_log_info_for_monitor.Title_Length=htons(8);
    ud_log_info_for_monitor.Title=(unsigned char *)malloc((int)(ud_log_info_for_monitor.Title_Length));
    memset(ud_log_info_for_monitor.Title,0,(int)(ud_log_info_for_monitor.Title_Length));
    memcpy(ud_log_info_for_monitor.Title,"safe_log",8);
    ud_log_info_for_monitor.Content_Length=htonl(14);
    ud_log_info_for_monitor.Content=(unsigned char *)malloc((int)(ud_log_info_for_monitor.Content_Length));
    memset(ud_log_info_for_monitor.Content,0,(int)(ud_log_info_for_monitor.Content_Length));
    memcpy(ud_log_info_for_monitor.Content,"content of log",14);
    ud_log_info_for_monitor.Url_Length=htons(10);
    ud_log_info_for_monitor.Url=(unsigned char *)malloc((int)(ud_log_info_for_monitor.Url_Length));
    memset(ud_log_info_for_monitor.Url,0,(int)(ud_log_info_for_monitor.Url_Length));
    memcpy(ud_log_info_for_monitor.Url,"url of log",10);
    ud_log_info_for_monitor.Attachmentfile_Num=2;
    ud_log_info_for_monitor.attach_content_t=(struct monitor_attach_content *)malloc(ud_log_info_for_monitor.Attachmentfile_Num*sizeof(struct monitor_attach_content));
    memset(ud_log_info_for_monitor.attach_content_t,0,ud_log_info_for_monitor.Attachmentfile_Num*sizeof(struct monitor_attach_content));
    ud_log_info_for_monitor.attach_content_t[0].AttachmentfileName_Length=htons(11);
    ud_log_info_for_monitor.attach_content_t[0].AttachmentfileName=(unsigned char *)malloc(11);
    memset(ud_log_info_for_monitor.attach_content_t[0].AttachmentfileName,0,11);
    memcpy(ud_log_info_for_monitor.attach_content_t[0].AttachmentfileName,"Attachment1",11);
    ud_log_info_for_monitor.attach_content_t[1].AttachmentfileName_Length=htons(11);
    ud_log_info_for_monitor.attach_content_t[1].AttachmentfileName=(unsigned char *)malloc(11);
    memset(ud_log_info_for_monitor.attach_content_t[1].AttachmentfileName,0,11);
    memcpy(ud_log_info_for_monitor.attach_content_t[1].AttachmentfileName,"Attachment2",11);
    ud_log_info_for_monitor.GatherTime=htonl(5000);

    buf_bytes=sizeof(struct ud_header)+sizeof(ud_log_info_for_monitor.CommandID)+sizeof(ud_log_info_for_monitor.House_ID_Length)+\
            (unsigned int)ud_log_info_for_monitor.House_ID_Length+sizeof(ud_log_info_for_monitor.SourceIP_Length)+\
            (unsigned int)ud_log_info_for_monitor.SourceIP_Length+sizeof(ud_log_info_for_monitor.DestinationIP_Length)+\
            (unsigned int)ud_log_info_for_monitor.DestinationIP_Length+sizeof(ud_log_info_for_monitor.SrcPort)+\
            sizeof(ud_log_info_for_monitor.DestPort)+sizeof(ud_log_info_for_monitor.DomainName_Length)+\
            (unsigned int)(ntohs(ud_log_info_for_monitor.DomainName_Length))+sizeof(ud_log_info_for_monitor.ProxyType_Flag);

    if((ntohs(ud_log_info_for_monitor.ProxyType_Flag))!=0)
    {
        buf_bytes=buf_bytes+sizeof(ud_log_info_for_monitor.ProxyType)+sizeof(ud_log_info_for_monitor.ProxyIp_Length)+\
                (unsigned int)ud_log_info_for_monitor.ProxyIp_Length+sizeof(ud_log_info_for_monitor.ProxyPort);
    }

    buf_bytes=buf_bytes+sizeof(ud_log_info_for_monitor.Title_Length)+(unsigned int)(ntohs(ud_log_info_for_monitor.Title_Length))+\
            sizeof(ud_log_info_for_monitor.Content_Length)+(unsigned int)(ntohl(ud_log_info_for_monitor.Content_Length))+\
            sizeof(ud_log_info_for_monitor.Url_Length)+(unsigned int)(ntohs(ud_log_info_for_monitor.Url_Length))+\
            sizeof(ud_log_info_for_monitor.Attachmentfile_Num);

    if(ud_log_info_for_monitor.Attachmentfile_Num!=0)
    {
        for(int i=0;i<ud_log_info_for_monitor.Attachmentfile_Num;i++)
        {
            buf_bytes=buf_bytes+sizeof(ud_log_info_for_monitor.attach_content_t[i].AttachmentfileName_Length)+\
                    (unsigned int)(ntohs(ud_log_info_for_monitor.attach_content_t[i].AttachmentfileName_Length));
        }
    }

    buf_bytes=buf_bytes+sizeof(ud_log_info_for_monitor.GatherTime);
    ud_header_for_monitor.Packet_Length = buf_bytes;

    *out_buf = (unsigned char *)malloc(sizeof(unsigned char)*buf_bytes);
    msg_to_send_tmp=*out_buf;
    memset(*out_buf,0,sizeof(char)*buf_bytes);

    ud_header_for_monitor.Packet_Length=htonl(ud_header_for_monitor.Packet_Length);
    memcpy(*out_buf,&ud_header_for_monitor,sizeof(struct ud_header));

    msg_to_send_tmp=msg_to_send_tmp+sizeof(struct ud_header);
    memcpy(msg_to_send_tmp,ud_log_info_for_monitor.CommandID,10);
    msg_to_send_tmp=msg_to_send_tmp+10;
    memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.House_ID_Length),1);
    msg_to_send_tmp=msg_to_send_tmp+1;
    memcpy(msg_to_send_tmp,ud_log_info_for_monitor.House_ID,(int)ud_log_info_for_monitor.House_ID_Length);
    msg_to_send_tmp=msg_to_send_tmp+(int)ud_log_info_for_monitor.House_ID_Length;
    memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.SourceIP_Length),1);
    msg_to_send_tmp=msg_to_send_tmp+1;
    memcpy(msg_to_send_tmp,ud_log_info_for_monitor.SrcIp,(int)ud_log_info_for_monitor.SourceIP_Length);
    msg_to_send_tmp=msg_to_send_tmp+(int)ud_log_info_for_monitor.SourceIP_Length;
    memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.DestinationIP_Length),1);
    msg_to_send_tmp=msg_to_send_tmp+1;
    memcpy(msg_to_send_tmp,ud_log_info_for_monitor.DestIp,(int)ud_log_info_for_monitor.DestinationIP_Length);
    msg_to_send_tmp=msg_to_send_tmp+(int)ud_log_info_for_monitor.DestinationIP_Length;
    memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.SrcPort),2);
    msg_to_send_tmp=msg_to_send_tmp+2;
    memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.DestPort),2);
    msg_to_send_tmp=msg_to_send_tmp+2;
    memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.DomainName_Length),2);
    msg_to_send_tmp=msg_to_send_tmp+2;

    if((ntohs(ud_log_info_for_monitor.DomainName_Length))!=0)
    {
        memcpy(msg_to_send_tmp,ud_log_info_for_monitor.DomainName,(int)(ntohs(ud_log_info_for_monitor.DomainName_Length)));
        msg_to_send_tmp=msg_to_send_tmp+(int)(ntohs(ud_log_info_for_monitor.DomainName_Length));
    }
    memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.ProxyType_Flag),2);
    msg_to_send_tmp=msg_to_send_tmp+2;
    if((ntohs(ud_log_info_for_monitor.ProxyType_Flag))!=0)
    {
        memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.ProxyType),2);
        msg_to_send_tmp=msg_to_send_tmp+2;
        memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.ProxyIp_Length),1);
        msg_to_send_tmp=msg_to_send_tmp+1;
        memcpy(msg_to_send_tmp,ud_log_info_for_monitor.ProxyIp,(int)ud_log_info_for_monitor.ProxyIp_Length);
        msg_to_send_tmp=msg_to_send_tmp+(int)ud_log_info_for_monitor.ProxyIp_Length;
        memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.ProxyPort),2);
        msg_to_send_tmp=msg_to_send_tmp+2;
    }
    memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.Title_Length),2);
    msg_to_send_tmp=msg_to_send_tmp+2;
    if((ntohs(ud_log_info_for_monitor.Title_Length))!=0)
    {
        memcpy(msg_to_send_tmp,ud_log_info_for_monitor.Title,(int)(ntohs(ud_log_info_for_monitor.Title_Length)));
        msg_to_send_tmp=msg_to_send_tmp+(int)(ntohs(ud_log_info_for_monitor.Title_Length));
    }
    memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.Content_Length),4);
    msg_to_send_tmp=msg_to_send_tmp+4;

    if((ntohl(ud_log_info_for_monitor.Content_Length))!=0)
    {
        memcpy(msg_to_send_tmp,ud_log_info_for_monitor.Content,(int)(ntohl(ud_log_info_for_monitor.Content_Length)));
        msg_to_send_tmp=msg_to_send_tmp+(int)(ntohl(ud_log_info_for_monitor.Content_Length));
    }

    memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.Url_Length),2);
    msg_to_send_tmp=msg_to_send_tmp+2;

    if((ntohs(ud_log_info_for_monitor.Url_Length))!=0)
    {
        memcpy(msg_to_send_tmp,ud_log_info_for_monitor.Url,(int)(ntohs(ud_log_info_for_monitor.Url_Length)));
        msg_to_send_tmp=msg_to_send_tmp+(int)(ntohs(ud_log_info_for_monitor.Url_Length));
    }

    memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.Attachmentfile_Num),1);
    msg_to_send_tmp=msg_to_send_tmp+1;
    if(ud_log_info_for_monitor.Attachmentfile_Num!=0)
    {
        for(int i=0;i<ud_log_info_for_monitor.Attachmentfile_Num;i++)
        {
            memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.attach_content_t[i].AttachmentfileName_Length),2);
            msg_to_send_tmp = msg_to_send_tmp + 2;
            memcpy(msg_to_send_tmp,ud_log_info_for_monitor.attach_content_t[i].AttachmentfileName,ntohs(ud_log_info_for_monitor.attach_content_t[i].AttachmentfileName_Length));
            msg_to_send_tmp=msg_to_send_tmp+ntohs(ud_log_info_for_monitor.attach_content_t[i].AttachmentfileName_Length);
        }
    }

    memcpy(msg_to_send_tmp,&(ud_log_info_for_monitor.GatherTime),4);
    msg_to_send_tmp = msg_to_send_tmp + 4;

    return buf_bytes;

}

int cls_pkt_processor::assemble_filter_log_packet(unsigned char **out_buf)
{
    unsigned char * msg_to_send_tmp = NULL;
    unsigned long buf_bytes=0;

    return buf_bytes;
}

void cls_pkt_processor::Initialize()
{
	int ret = 0;
	ISMS_ply_upd_time = 0;
	delt1 = 0;
	delt2 = 0;
	delt3 = 0;
	delt4 = 0;
	delt5 = 0;
	http_num=0;
	if (ret = ClsDBOperation.connect_db("localhost", "root", "tma1100", "db_idc"))
	{
		printf("Initialize(): connect database failed, exit!!!!!\n");
		exit(1);
	}

	sock_reset = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock_reset == -1)
	{
		printf("Initialize(): create sock_reset error, exit!!!!!\n");
		exit(1);
	}

	printf("CDPDKRingReader Initialize(): initialize mwm_handle\n");
	mwm_handle = NULL;
	mwm_handle = mwmNew();

    bzero(house_id, sizeof(house_id));
    bzero(house_ip, sizeof(house_ip));
	ClsDBOperation.get_EU_CommInfo(house_id);
    printf("Initialize(): read_house_id over, %s %s\n", house_id, house_ip);

	load_ISMS_policies();

    serv_port_policy_update = client_port_ud_log = client_port_ud_attach = 0;
    read_comm_conf_from_file();
    printf("Initialize(): read comm conf, %d %d %d\n", serv_port_policy_update, client_port_ud_log, client_port_ud_attach);

	udp_comm = new CUDPServer(serv_port_policy_update);
	tcp_comm = new CTCPServer();
	printf("Initialize(): UDPServer and TCPServer initialization over.......\n");


	map_result.clear();
    pthread_t  hdl_temp;
    pthread_create(&hdl_temp, NULL, radom_work_func, this);
	
	printf("Initialize(): initialization working over!\n");

	
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

void *cls_pkt_processor::radom_work_func(void* arg)
{
    cls_pkt_processor *obj = (cls_pkt_processor *)arg;
    obj->do_radom_work(arg);
}


void cls_pkt_processor::do_radom_work(void* arg)
{
    printf("do_radom_work thread is running.......\n");
    static int file_index = 0;

    while(1)
    {
    	sleep(5);
		printf("################packet_num=%u,http_num=%d\n",cap_pkt_cnt,http_num);
		printf("$$$$$$$$$$$$$$$$tcp=%llu,http=%llu,trunck=%llu,unzip=%llu,mwm=%llu\n",delt1,delt2,delt3,delt4,delt5);
		printf("num_conn: %lu, req_packet:%lu,resp_packet:%lu,req_sdu:%lu,resp_sdu:%lu,req:%lu,resp:%lu, other: %lu\n", 
                num_tcp_conn, num_http_req_pkt_recv, num_http_resp_pkt_recv, num_http_req_sdu_data, 
                num_http_resp_sdu_data, num_http_req_data, num_http_resp_data, num_http_other_data);

		printf("11111111111111111, %d\n", map_result.size());
		MapMatchRslt::iterator ptr = map_result.begin();
		stru_match_rslt& t = ptr->second;
		for (; ptr != map_result.end(); ptr++)
		{
			stru_match_rslt  temp_rslt = ptr->second;
			printf("url+host = <%s>, bingo_policy = %u, bingo_cache = %u\n", (ptr->first).c_str(), 
                    temp_rslt.bingo_policy, temp_rslt.bingo_cache);
		}
    	continue;
    }
}
  
void cls_pkt_processor::packet_processer(unsigned char *arg, const struct pcap_pkthdr *ph, const unsigned char *packet)
{
    LLHeadStru            struLLHead;
    L3HeadStru            struL3Head;
    UDPHeadStru           struUDPHead;
    TCPHeadStru           struTCPHead;
    L4HeadUnion           unionL4Head;
    unsigned char         *pContent;
    unsigned int          caplen;
    unsigned int          ll_head_len;
    unsigned int          ip_head_len, iplen;
    unsigned int          tcp_head_len;
    unsigned int          content_len;

    caplen = ph->caplen;
    struLLHead = *(LLHeadStru *)packet;
    struLLHead.protocol = ntohs(struLLHead.protocol);

	cap_pkt_cnt++;
#ifdef __PRINT_LOG
	printf("\n\npacket_processer: recv (((((((%lu)))))) packet, caplen = %d\n", cap_pkt_cnt, caplen);
#endif

    pContent = NULL;

    if (struLLHead.protocol==IP_PROTO)
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

    if (caplen < ll_head_len)
    {
        return;
    }
    unsigned char *pPacket_begin  = NULL;
    pPacket_begin = (unsigned char*)packet;

    struL3Head = *(L3HeadStru *)(pPacket_begin + ll_head_len);
    struL3Head.source_addr = ntohl(struL3Head.source_addr);
    struL3Head.dest_addr = ntohl(struL3Head.dest_addr);
    struL3Head.total_len = ntohs(struL3Head.total_len);

    ip_head_len = (struL3Head.version & 0x0f) * 4;

    iplen = (struL3Head.total_len > caplen)? caplen:struL3Head.total_len;
    if (ip_head_len > iplen)
    {
        ip_head_len = 20; // minimum len for ip header in case of SERIOUS ABNORMALTY
    }

    if (caplen < SIZE_LL_HEAD + ip_head_len||struL3Head.total_len > caplen)
    {
        return;
    }

    // deal with the head sector according the protocol of 3rd layer
    switch (struL3Head.protocol)
    {
        case  TCP_PROTO:
            struTCPHead = *(TCPHeadStru *)(pPacket_begin + ll_head_len + ip_head_len);
            struTCPHead.source_port = ntohs(struTCPHead.source_port);
            struTCPHead.dest_port = ntohs(struTCPHead.dest_port);
            struTCPHead.seq_num = ntohl(struTCPHead.seq_num);
            struTCPHead.ack_num = ntohl(struTCPHead.ack_num);
            unionL4Head.TCPHead = struTCPHead;
            tcp_head_len = ((struTCPHead.header_len & 0xf0) >> 4) * 4;
            if ((tcp_head_len + ip_head_len) > iplen)
            {
                tcp_head_len = (iplen - ip_head_len < 0)? 0:iplen - ip_head_len;
            }
            pContent = /*(char *)*/(pPacket_begin + ll_head_len + ip_head_len + tcp_head_len);
            content_len = iplen - ip_head_len - tcp_head_len;
            if (caplen < ll_head_len + ip_head_len + tcp_head_len)
            {
                return;
            }

            break;
        case  UDP_PROTO:
            struUDPHead = *(UDPHeadStru *)(pPacket_begin + ll_head_len + ip_head_len);
            struUDPHead.source_port = ntohs(struUDPHead.source_port);
            struUDPHead.dest_port = ntohs(struUDPHead.dest_port);
            unionL4Head.UDPHead = struUDPHead;
            content_len = iplen - ip_head_len - SIZE_UDP_HEAD;
            if (content_len < 0)
            {
                content_len = 0;
                pContent =/*(char *)*/(pPacket_begin + ll_head_len + ip_head_len);
            }
            else
                pContent =/*(char *)*/(pPacket_begin + ll_head_len + ip_head_len + SIZE_UDP_HEAD);
            if (caplen < ll_head_len + ip_head_len + SIZE_UDP_HEAD)
            {
                return;
            }
            break;

        default:
            memset(&unionL4Head, 0, sizeof(L4HeadUnion));
            pContent =/*(char *)*/(pPacket_begin + ll_head_len + ip_head_len);
            content_len = iplen - ip_head_len;
    }

    if (pContent == NULL)
        return;

    //  END OF switch (struL3Head.protocol)
    if (content_len < 0)
        content_len = 0;

    unsigned short        sport = 0, dport = 0;

    sport = unionL4Head.TCPHead.source_port;
    dport = unionL4Head.TCPHead.dest_port;

    if(sport == 22 || dport == 22)
    {
        return;
    }

    unsigned int sip = struL3Head.source_addr;
    unsigned int dip = struL3Head.dest_addr;


    char str_sip[16], str_dip[16];
    bzero(str_sip, sizeof(str_sip));
    bzero(str_dip, sizeof(str_dip));

    struct in_addr addr;
    addr.s_addr = htonl(sip);
    strcpy(str_sip, inet_ntoa(addr));
    addr.s_addr = htonl(dip);
    strcpy(str_dip, inet_ntoa(addr));
    //printf("packet_processer: sip = %u, dip = %u, sport = %d, dport = %d\n", sip, dip, (int)sport, (int)dport);
#ifdef __PRINT_LOG
    printf("packet_processer: sip = %s, sport = %d, dip = %s, dport = %d, caplen = %d, len = %d, content_len = %d\n",
           str_sip, (int)sport, str_dip, (int)dport, ph->caplen, ph->len, content_len);
#endif

    // only the TCP packet will be processed
    if (struL3Head.protocol != TCP_PROTO)
    {
        return;
    }

    if (content_len == 0 && (struL3Head.flag&0x4)!=0x4)
    {
#ifdef __PRINT_LOG
        printf("packet_processer: content_len == 0, return!\n");
#endif
        return;
    }
    else
	{
#ifdef __PRINT_LOG
        printf("packet_processer: content_len = %d, addr_pContent = %p, addr_packet = %p\n", content_len, pContent, packet);
#endif
	}


    DoTCPPacketProcess(&struLLHead,
                        &struL3Head,
                        &struTCPHead,
                        struL3Head.source_addr,
                        struTCPHead.source_port,
                        struL3Head.dest_addr,
                        struTCPHead.dest_port,
                        pContent,
                        content_len);

}

int cls_pkt_processor::DoTCPPacketProcess(const LLHeadStru *pStruLLHead,
                                          const L3HeadStru *pStruL3Head,
                                          const TCPHeadStru *pStruTCPHead,
                                          unsigned int sip,
                                          unsigned short sport,
                                          unsigned int dip,
                                          unsigned short dport,
                                          const unsigned char *pContent,
                                          const unsigned int content_len)
{
    if (unlikely(pStruL3Head->protocol != TCP_PROTO))
    //if (pStruL3Head->protocol != TCP_PROTO)
        return 0;

	// AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaa
	//return 0;



    unsigned char     *sdu_data = NULL;
    unsigned int      sdu_len = 0;
    enum TCPDirection tcp_dir = DIR_NONE;
    int               dir = 0;

    TCPsessionID      tcp_id = {TCP_PROTO, sip, dip, sport, dport};



	struct timeval t1;
	struct timeval t2;
	gettimeofday(&t1,NULL);
	int doTcpRet = 0;
    doTcpRet = ClsTCPReassemble.do_tcp_reassemble(sip, dip, sport, dport,
                                           &dir, (TCPHeadStru*)pStruTCPHead, pContent, content_len,
                                           &sdu_len, &sdu_data);
	gettimeofday(&t2,NULL);
	delt1 += (t2.tv_sec-t1.tv_sec)*1000000+(t2.tv_usec-t1.tv_usec);
	if((doTcpRet&0x1) != TCP_SEG_RECVED)
    {
        printf("DoTCPPacketProcess: (8) do_tcp_reassemble return not TCP_SEG_RECVED, return 0\n");
        return 0;
    }


#ifdef __PRINT_LOG
    printf("DoHttpParserPlugin: process_tcp_packet_EC return TCP_SEG_RECVED, len = %d, content as follows:\n", sdu_len);
#endif

    int i = 0, j = 0;
#if 0
	//if (cap_pkt_cnt== 8)
	{
    	for (i = 0; i < sdu_len; i++)
    	{
        	printf("%02X ", sdu_data[i]);
        	j++;

        	if (j % 8 == 0)
            	printf("  ");
        	if (j % 16 == 0)
            	printf("\n");

    	}
    	printf("\n");
	}
#endif

	// EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
	/*
	free(sdu_data);
	sdu_data = NULL;
	return 0;
	*/

    // http_head对当前报文进行http解析的结果
    stru_http_header  http_head;
    bzero(&http_head, sizeof(http_head));
    ClsHTTPUrlCache.get_http_req_head(sdu_data, sdu_len, &http_head);

	if (http_head.method == 1 || http_head.method == 2)
	{
		num_http_req_pkt_recv++;
	}
	else if (http_head.method == 3)
	{
		num_http_resp_pkt_recv++;
	}


    unsigned int http_data_len = 0;
    unsigned char *http_data = NULL;
	unsigned int  unzip_len = 0;
	unsigned char *unzip_buf = NULL;


	stru_http_req_head temp_http_header;
	bzero(&temp_http_header, sizeof(temp_http_header));
    temp_http_header.method = (HTTP_METHOD)http_head.method;
    // 根据TCP重组得到的报文进行HTTP重组,传入http_head的目的是为了在http_hash_tbl中保存相应的
    // url和host,以便在返回一个HTTP RESP时能够将相应的url和host一起返回,供cache操作使用.
	printf("DoTCPProcess: (10) go on to do_http_reassemble: temp_http_header.method = %d\n", temp_http_header.method);

	int http_type = 0;

	gettimeofday(&t1,NULL);
    char ret = ClsHTTPReassemble.do_http_reassemble(tcp_id, sdu_len, sdu_data, &temp_http_header, (enum TCPDirection)dir,
                                         &http_data_len, &http_data, &http_type);
	gettimeofday(&t2,NULL);
	delt2 += (t2.tv_sec-t1.tv_sec)*1000000+(t2.tv_usec-t1.tv_usec);

	//free(sdu_data);
	//sdu_data = NULL;
    
    if (likely(ret != 0))
    //if (ret != 0)
    {
#ifdef __PRINT_LOG
        printf("DoTCPProcess: (10) do_http_reassmeble return not a http req or resp, return!!!!!\n");
#endif
		return 0;
    }
    else
    {
	http_num++;
#ifdef __PRINT_LOG
        printf("[%d]DoTCPProcess: (10) do_http_reassmeble return a new http req/resp, content_len(include header) = %d, go on doing!!!\n", http_num,http_data_len);
	    printf("DoTCPProcess: (10) do_http_reassemble: chunk_flag = %d, gzip_flag = %d, content_type = (%s)\n", \
               temp_http_header.chunk_flag, temp_http_header.gzip_flag, temp_http_header.content_type);
#endif

		if (http_type == 1)
		{
    		free(http_data);
    		http_data = NULL;
			num_http_other_data++;
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
    printf("DoTCPProcess: (10) getted http data, addr = %p, len = %d, content is as follows:\n", http_data, http_data_len);
    i = 0;  
    j = 0;  
    for (i = 0; i < http_data_len; i++)
    { 
        printf("%02X ", http_data[i]);
        j++;    
        if (j % 8 == 0) 
            printf("  ");
        if (j % 16 == 0)
            printf("\n");
    }
    printf("\n");
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
	gettimeofday(&t1,NULL);
        ret = ClsHTTPReassemble.dechunk_data(http_data, &http_data_len);
	gettimeofday(&t2,NULL);
	delt3 += (t2.tv_sec-t1.tv_sec)*1000000+(t2.tv_usec-t1.tv_usec);
        if (ret != 0)
        {
#ifdef __PRINT_LOG
            printf("chunked data, dechunk failed, free data.......\n");
#endif
            goto LABEL_FREE_HTTP_DATA;
        }

        if (unlikely(http_data_len >= old_len))
        //if (http_data_len >= old_len)
        {
#ifdef __PRINT_LOG
            printf("chunked_data, dechunk length error, free data......\n");
#endif
            goto LABEL_FREE_HTTP_DATA;
        }
#ifdef __PRINT_LOG 
		printf("chunk_data, dechunk success, dechunk_data_len(include header) = %d\n", http_data_len);
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
    printf("unzip_data, addr of to be unzipped buf = %p\n", http_data);
#endif
	gettimeofday(&t1,NULL);
    ret = ClsHTTPReassemble.unzip_data(http_data, http_data_len, &unzip_buf, &unzip_len);

	gettimeofday(&t2,NULL);
	delt4 += (t2.tv_sec-t1.tv_sec)*1000000+(t2.tv_usec-t1.tv_usec);
LABEL_FREE_HTTP_DATA:
    free(http_data);
    http_data = NULL;

    
    if (unlikely(unzip_buf == NULL || ret != 0))
    //if (unzip_buf == NULL || ret != 0)
    {
#ifdef __PRINT_LOG
        printf("unzip data, unzip failed, free data......\n");
#endif
        goto LABEL_FREE_UNZIP_DATA;
    }

    printf("pktno: %lu, unzip data, unzip success, unzip_len = %d\n", cap_pkt_cnt, unzip_len);
#ifdef __PRINT_LOG
    printf("pktno: %lu, unzip data, unzip success, unzip_len = %d\n", cap_pkt_cnt, unzip_len);
#endif

	// IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
    //goto LABEL_FREE_UNZIP_DATA;

    //if (temp_http_header.type_text_flag)
	if (1)
    {
#ifdef __PRINT_LOG
        printf("unzip_len = %d, content = (((((%s)))))\n", unzip_len, unzip_buf);
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
gettimeofday(&t1,NULL);
        ListRuleInfo bing_list = do_keyword_match(pStruLLHead,
                         pStruL3Head,
                         pStruTCPHead,
                         sip,dip,sport,dport,
                         unzip_buf,unzip_len);
	gettimeofday(&t2,NULL);
	delt5 += (t2.tv_sec-t1.tv_sec)*1000000+(t2.tv_usec-t1.tv_usec);

		// do_keyword_match应该返回一个包含mwm命中关键字对应rule所在的policy的索引list，如果
        // 这个list不为空，则检查此连接上的策略命中位图，如果已经全命中了一些策略，则取出
        // 对应优先级最高的那个策略，按照其定义对此连接上的当前及后续处理进行处理
    }

LABEL_FREE_UNZIP_DATA:
    if (unzip_buf != NULL)
    {
        free(unzip_buf);
        unzip_buf = NULL;
    }

    return 0;

}

void cls_pkt_processor::update_map_rslt_info(char *host, char *url, int type)
{
	string key = "";
	key += host;
	key += "/";
	key += url;


#ifdef __PRINT_LOG
	//printf("update_map_rslt_info: host: <%s>, url: <%s>, type = %u\n", host, url, type);
#endif
	MapMatchRslt::iterator ptr = map_result.find(key);
	if (ptr != map_result.end())
	{
		if (type)
		{
			((ptr->second).bingo_policy) ++;
#ifdef __PRINT_LOG
		printf("update_map_rslt_info: 1111111111, host: <%s>, url: <%s>, bing_policy = %u\n", host, url, (ptr->second).bingo_policy);
#endif
		}
		else
		{
			((ptr->second).bingo_cache)++;
#ifdef __PRINT_LOG
		printf("update_map_rslt_info: 1111111111, host: <%s>, url: <%s>, bing_cache = %u\n", host, url, (ptr->second).bingo_cache);
#endif
		}
	}
	else
	{
		stru_match_rslt temp = {0, 0};
		if (type)
		{
			(temp.bingo_policy) = 1;
			(temp.bingo_cache) = 0;
#ifdef __PRINT_LOG
		    printf("update_map_rslt_info: 2222222222, host: <%s>, url: <%s>, type = %u, bingo_policy = %u, bingo_cache = %u\n", 
                   host, url, type, temp.bingo_policy, temp.bingo_cache);
#endif
		}
		else
		{
			(temp.bingo_policy) = 0;
			(temp.bingo_cache) = 1;
#ifdef __PRINT_LOG
		    printf("update_map_rslt_info: 2222222222, host: <%s>, url: <%s>, type = %u, bingo_policy = %u, bingo_cache = %u\n", 
                   host, url, type, temp.bingo_policy, temp.bingo_cache);
#endif
		}

		map_result.insert(pair<string, stru_match_rslt>(key, temp));
#ifdef __PRINT_LOG
		//printf("update_map_rslt_info: 2222222222, host: <%s>, url: <%s>, type = %u\n", host, url, type);
#endif
		
	}
}



// end of the file

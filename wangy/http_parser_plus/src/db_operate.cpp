#include "db_operate.h"
#include "BitMap.h"

cls_db_operation::cls_db_operation()
{
}

char cls_db_operation::connect_db(const char* host, const char* user, const char* password, const char* database)
{
    mysql_init(&db_conn);
	if (mysql_real_connect(&db_conn, host, user, password, database, 0, NULL, 0))
	{
    	printf("cls_db_operation: 111111111111111 connect mysql success\n");
		return 0;
	}
	else
	{
		mysql_error(&db_conn);
    	printf("cls_db_operation: 222222222222222 connect mysql failed!\n");
		return 1;
	}
}

cls_db_operation::~cls_db_operation()
{
}

char cls_db_operation::get_EU_CommInfo(char *house_id)
{
	MYSQL_ROW row;
    MYSQL_RES *res;

	string sql = "select * from tbl_EU_dev_common_info where seqno in (select max(seqno) from tbl_EU_dev_common_info);";
	int t = mysql_query(&db_conn, sql.c_str()); 
	if (t)
	{
		printf("get_EU_CommInfo(): mysql_query(%s) failed!\n", sql.c_str());
	}
	else
	{
		printf("get_EU_CommInfo(): mysql_query success!\n");
		res = mysql_store_result(&db_conn);
        if(res)
        {
            for(int r = 0; r < mysql_num_rows(res); r++)
            {
                row = mysql_fetch_row(res);

                for(t=0;t<mysql_num_fields(res);t++)
                     printf("%s ",row[t]);
                printf("\n");
				printf("row[4] = %s\n", row[4]);
				strcpy(house_id, row[4]);
            }
        }
        mysql_free_result(res);
	}
}


char cls_db_operation::get_ISMS_policy(char *house_id, vector<stru_ISMS_policy> &vector_policy)
{

	MYSQL_ROW row;
	MYSQL_RES *res;

	string str_house_id(house_id);

	//string sql = "select * from tbl_ISMS_policy_info a, tbl_ISMS_policy_rule_info b where a.MessageNo = b.MessageNo;";
	//string sql = "select * from tbl_ISMS_policy_info a inner join tbl_ISMS_policy_rule_info b on a.MessageNo = b.MessageNo and a.Bind_Status = 1 ORDER BY a.MessageNo;";
	string sql = "select * from tbl_ISMS_policy_info a inner join tbl_ISMS_policy_rule_info b on a.MessageNo = b.MessageNo and a.Bind_Status = 1";
	sql = sql + " and a.Bind_HouseID = '" + str_house_id + "'" + " ORDER BY a.MessageNo;";
	printf("sql: (((((%s)))))\n", sql.c_str());
	int t = mysql_query(&db_conn, sql.c_str());
	if (t)
	{
		printf("get_ISMS_policy(): mysql_query(%s) failed!\n", sql.c_str());
	}
	else
	{
		printf("get_ISMS_policy(): mysql_query success!\n");
		res = mysql_store_result(&db_conn);
		if (res)
		{
			vector_policy.clear();
			printf("get_ISMS_policy(): there are %d rows in the query_result\n", mysql_num_rows(res));

			unsigned long last_msgno = 0;
			int last_index = 0;
			for (int r = 0; r < mysql_num_rows(res); r++)
			{
				row = mysql_fetch_row(res);
				
				stru_ISMS_policy  temp_policy;
				bzero(&temp_policy, sizeof(temp_policy));
				temp_policy.vector_rule.clear();

				sscanf(row[1], "%lu", &(temp_policy.MsgNo));
				sscanf(row[2], "%s", temp_policy.CmdID);
				sscanf(row[3], "%d", &(temp_policy.Type));
				sscanf(row[4], "%d", &(temp_policy.RuleNum));
				sscanf(row[5], "%d", &(temp_policy.BlockFlag));
				sscanf(row[6], "%d", &(temp_policy.LogFlag));
				sscanf(row[7], "%d", &(temp_policy.Level));
				sscanf(row[8], "%lu", &(temp_policy.EffectTime));
				sscanf(row[9], "%lu", &(temp_policy.ExpireTime));
				sscanf(row[10], "%lu", &(temp_policy.MsgSerialNo));
				sscanf(row[11], "%d", &(temp_policy.BindStatus));
				sscanf(row[12], "%s", &(temp_policy.BindHouseID));
				sscanf(row[13], "%lu", &(temp_policy.UpdateTime));

				struct stru_ISMS_policy_rule temp_rule;
				bzero(&temp_rule, sizeof(temp_rule));
				sscanf(row[15], "%d", &(temp_rule.Rule_SubType));
				sscanf(row[16], "%s", temp_rule.Rule_Host);
				sscanf(row[17], "%s", temp_rule.Rule_Url);
				sscanf(row[18], "%d", &(temp_rule.Rule_ProtoL4));
				sscanf(row[19], "%lu", &(temp_rule.Rule_SipStart));
				sscanf(row[20], "%lu", &(temp_rule.Rule_SipEnd));
				sscanf(row[21], "%lu", &(temp_rule.Rule_DipStart));
				sscanf(row[22], "%lu", &(temp_rule.Rule_DipEnd));
				sscanf(row[23], "%d", &(temp_rule.Rule_SportStart));
				sscanf(row[24], "%d", &(temp_rule.Rule_SportEnd));
				sscanf(row[25], "%d", &(temp_rule.Rule_DportStart));
				sscanf(row[26], "%d", &(temp_rule.Rule_DportEnd));
				sscanf(row[27], "%s", temp_rule.Rule_Keyword);
				sscanf(row[28], "%d", &(temp_rule.Rule_KeyRange));

				if (temp_policy.Type == 6)
					temp_policy.Level = 1;
				else if (temp_policy.Type == 2)
					temp_policy.Level = 1024;
				else if (temp_policy.Type == 1)
					temp_policy.Level = 2048;

				if (last_msgno == 0)
				{
					temp_policy.vector_rule.push_back(temp_rule);
					vector_policy.push_back(temp_policy);

					temp_rule.policy_index = last_index = 0;
					last_msgno = temp_policy.MsgNo;
				}
				else if (last_msgno == temp_policy.MsgNo)
				{
					temp_rule.policy_index = last_index;
					vector_policy[last_index].vector_rule.push_back(temp_rule);
				}
				else if (last_msgno != temp_policy.MsgNo)
				{
					temp_rule.policy_index = ++last_index;
					temp_policy.vector_rule.push_back(temp_rule);
					vector_policy.push_back(temp_policy);

					last_msgno = temp_policy.MsgNo;
				}
				else
				{
				}
			}
		}

		
	}

#if 0
	size_t len = vector_policy.size();
	printf("\n\n*******************************************************\n", len);
	printf("There are %d ISMS policies totally\n", len);
	stru_ISMS_policy  temp_policy;
	for (size_t i = 0; i < len; i++)
	{
		printf("---------------------------------------------------------\n");
		temp_policy = vector_policy[i];
		printf("ISMS_policy[%d].MsgNo: %lu\n", i, temp_policy.MsgNo);
		printf("ISMS_policy[%d].MsgNo: %s\n", i, temp_policy.CmdID);
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
		
		size_t len_rule = temp_policy.vector_rule.size();
		struct stru_ISMS_policy_rule temp_rule;
		for (size_t j = 0; j < len_rule; j++)
		{
			temp_rule = temp_policy.vector_rule[j];
			printf("\trule[%d].policy_index: %d\n", j, temp_rule.policy_index);
			printf("\trule[%d].Rule_SubType: %d\n", j, temp_rule.Rule_SubType);
			switch(temp_rule.Rule_SubType)
			{
			case 1:
				printf("\trule[%d].Rule_Host: %s, domain rule\n", j, temp_rule.Rule_Host);
				break;
			case 2:
				printf("\trule[%d].Rule_Url: %s, URL rule\n", j, temp_rule.Rule_Url);
				break;
			case 3:
				printf("\trule[%d].Rule_Keyword: range = %d, %s, Keyword rule\n", j, temp_rule.Rule_KeyRange, temp_rule.Rule_Keyword);
				break;
			case 4:
				printf("\trule[%d].Rule_SIP, start = %lu, end = %lu, SIP rule\n", j, temp_rule.Rule_SipStart, temp_rule.Rule_SipEnd);
				break;
			case 5:
				printf("\trule[%d].Rule_DIP, start = %lu, end = %lu, DIP rule\n", j, temp_rule.Rule_DipStart, temp_rule.Rule_DipEnd);
				break;
			case 6:
				printf("\trule[%d].Rule_Sport, start = %d, end = %d, Sport rule\n", j, temp_rule.Rule_SportStart, temp_rule.Rule_SportEnd);
				break;
			case 7:
				printf("\trule[%d].Rule_Dport, start = %d, end = %d, Dport rule\n", j, temp_rule.Rule_DportStart, temp_rule.Rule_DportEnd);
				break;
			case 8:
				printf("\trule[%d].Rule_ProtoL4: %d, Proto rule\n", j, temp_rule.Rule_ProtoL4);
				break;
			default:
				break;
			}
		}
		printf("---------------------------------------------------------\n");
	}
	printf("*******************************************************\n", len);
#endif
}

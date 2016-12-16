#include <pty.h>
#include <mysql/mysql.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <vector>
#include <string>


#include "data_def.h"

using namespace std;


class cls_db_operation
{
public:
	cls_db_operation();
	~cls_db_operation();

	char get_EU_CommInfo(char *house_id);
	char get_ISMS_policy(char *house_id, vector<stru_ISMS_policy> &vector_policy);
	char connect_db(const char* host, const char* user, const char* password, const char* database);

private:
	MYSQL    db_conn;

};

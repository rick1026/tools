#########################################################################
# File Name: alter.sh
# Author: ma6174
# mail: ma6174@163.com
# Created Time: Fri 01 Sep 2017 10:28:21 AM CST
#########################################################################
#!/bin/bash
su - pg << EOF
    /database/pgsql-9.6.2/bin/psql db_test << E2
	alter table tr_service_map add normappconent  integer NOT NULL default 0;
E2
EOF

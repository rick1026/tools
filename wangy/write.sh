#!/bin/bash

MessageNo=1000001

for ((i=0;i<10000;i++))
do
echo " insert into tbl_ISMS_policy_info(MessageNo,Type,Rule_Num,Log_Flag,level,Bind_Status)values($MessageNo,6,1,1,0,1);">>1.sql
echo "insert into tbl_ISMS_policy_rule_info(MessageNo,Rule_SubType,Rule_sip_start, Rule_sip_end)values($MessageNo,4,3232236297, 3232236297);" >>1.sql
((MessageNo++))
done

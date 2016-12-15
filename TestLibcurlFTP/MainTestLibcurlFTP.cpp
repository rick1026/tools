/*
 * MainTestLibcurlFTP.cpp
 *
 *  Created on: 2016年5月30日
 *      Author: zhangjl
 */
#include "ClsLibcurlFTP.h"

int main(int argc, char **argv)
{
	ClsLibcurlFTP  download_obj;

	int fail_times = 0;
	int dl_timeout = 5, dl_tries = 3;
	do
	{
		char ret = download_obj.ftp_download_continue_transfer("qzt", "beappaeb",
			"ftp://121.14.204.19/patch_3.4.7.1_3.4.7.3.tgz",
			"/var/patch_3.4.7.1_3.4.7.3.tgz",
			dl_timeout,
			dl_tries);

		if (ret == CURL_FTP_SUCCESS)
			break;
		else
		{
			fail_times++;
			printf("[%u] download %d times failed, try again!\n", time(0), fail_times);
		}
	}while(fail_times < 10);

	return 0;
}

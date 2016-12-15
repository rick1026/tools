/*
 * ClsLibcurlFTP.h
 *
 *  Created on: 2016年5月30日
 *      Author: zhangjl
 */

#ifndef CLSLIBCURLFTP_H_
#define CLSLIBCURLFTP_H_

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <curl/curl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define CURL_FTP_FAIL        1
#define CURL_FTP_SUCCESS     0

class ClsLibcurlFTP {
public:
	ClsLibcurlFTP();
	virtual ~ClsLibcurlFTP();

	void set_ftp_user(char *user);
	void set_ftp_pass(char *pass);

	char download_by_ftp(const char *remotepath, const char *localpath, unsigned long timeout, int tries);
	char download_by_ftp(const char *username, const char *passwd, const char *remotepath, const char *localpath,
			unsigned long dl_timeout, int tries);
	char ftp_download_continue_transfer(const char *username, const char *passwd, const char *remotepath, const char *localpath,
			unsigned long dl_timeout, int tries);

private:


private:
	char   ftp_user[64];
	char   ftp_pass[64];


};

#endif /* CLSLIBCURLFTP_H_ */

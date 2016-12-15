/*
 * ClsLibcurlFTP.cpp
 *
 *  Created on: 2016年5月30日
 *      Author: zhangjl
 */

#include "ClsLibcurlFTP.h"

size_t getcontentlengthfunc(void *ptr, size_t size, size_t nmemb, void *stream);
size_t writefunc(void *ptr, size_t size, size_t nmemb, void *stream);

ClsLibcurlFTP::ClsLibcurlFTP() {
	// TODO Auto-generated constructor stub

}

ClsLibcurlFTP::~ClsLibcurlFTP() {
	// TODO Auto-generated destructor stub
}

inline void ClsLibcurlFTP::set_ftp_user(char *username)
{
	memset(this->ftp_user, 0, sizeof(this->ftp_user));
	strncpy(this->ftp_user, username, sizeof(this->ftp_user) - 1);
	return;
}

inline void ClsLibcurlFTP::set_ftp_pass(char *passwd)
{
	memset(this->ftp_pass, 0, sizeof(this->ftp_pass));
	strncpy(this->ftp_pass, passwd, sizeof(this->ftp_pass) - 1);
	return;
}

char ClsLibcurlFTP::download_by_ftp(const char *remotepath, const char *localpath, unsigned long timeout, int tries)
{
	return CURL_FTP_SUCCESS;
}

char ClsLibcurlFTP::download_by_ftp(const char *username, const char *passwd,
		const char *remotepath, const char *localpath,
		unsigned long dl_timeout, int tries)
{
	if (username == NULL || passwd == NULL || remotepath == NULL || localpath == NULL)
	{
		return CURL_FTP_FAIL;
	}

	char ret = CURL_FTP_SUCCESS;
	char user_pass[128];
	memset(user_pass, 0, sizeof(user_pass));
	snprintf(user_pass, sizeof(user_pass) - 1, "%s:%s", username, passwd);

	FILE *f = NULL;
	CURL *curlhandle = NULL;
	CURLcode r = CURLE_GOT_NOTHING;


	printf("[%u] download : remotefile[%s], localfile[%s], user[%s], passwd[%s], timeout = %lu, tries_time = %d\n",
			time(0), remotepath, localpath, username, passwd, dl_timeout, tries);


	// open local file
	f = fopen(localpath, "w+");
	if (f == NULL)
	{
		printf("download: open localfile[%s] failed, errmsg = [%s]!\n", localpath, strerror(errno));
		return CURL_FTP_FAIL;
	}

	// call initialization function of libcurl, both is needed
	curl_global_init(CURL_GLOBAL_ALL);
	curlhandle = curl_easy_init();

	// set the options of libcurl action
	curl_easy_setopt(curlhandle, CURLOPT_URL, remotepath);
	curl_easy_setopt(curlhandle, CURLOPT_USERPWD, user_pass);
	curl_easy_setopt(curlhandle, CURLOPT_DNS_CACHE_TIMEOUT, 3600);

	// set the maxium time of the whole download action, from curl_easy_perform, 3600s
	if (dl_timeout)
		curl_easy_setopt(curlhandle, CURLOPT_TIMEOUT, dl_timeout);
	else
		curl_easy_setopt(curlhandle, CURLOPT_TIMEOUT, 3600);

	// set the maxium time of the connection to the server, 120s, not effective if value is bigger than 60s
	curl_easy_setopt(curlhandle, CURLOPT_CONNECTTIMEOUT, 120);
	// set the maxium time of generating the ftp_response for the server, 60s, not effective
	curl_easy_setopt(curlhandle, CURLOPT_FTP_RESPONSE_TIMEOUT, 60);

	// set CURLOPT_NOPROGRESS a not-zero value to shut off the built-in progress
	curl_easy_setopt(curlhandle, CURLOPT_NOPROGRESS, 1L);

	curl_easy_setopt(curlhandle, CURLOPT_WRITEDATA, f);
	// set not-zero value to display information

	FILE *fd_log = fopen("/home/zhangjl/curl_download.log", "w+");
	if (fd_log != NULL)
	{
		curl_easy_setopt(curlhandle, CURLOPT_VERBOSE, 1L);
		// set the stderr to the file pointed by fd_log
		curl_easy_setopt(curlhandle, CURLOPT_STDERR, fd_log);
	}
	else
		curl_easy_setopt(curlhandle, CURLOPT_VERBOSE, 0L);

	// set a buffer to store error messages
	char err_buf[CURL_ERROR_SIZE];
	memset(err_buf, 0, CURL_ERROR_SIZE);
	curl_easy_setopt(curlhandle, CURLOPT_ERRORBUFFER, err_buf);

	r = curl_easy_perform(curlhandle);
	if (r == CURLE_OK)
	{
		ret = CURL_FTP_SUCCESS;
	}
	else
	{
		ret = CURL_FTP_FAIL;
		printf("download: download fail(%s)\n", curl_easy_strerror(r));
	}

	fclose(f);
	curl_easy_cleanup(curlhandle);
	curl_global_cleanup();
	if (fd_log != NULL)
		fclose(fd_log);

	return ret;
}

char ClsLibcurlFTP::ftp_download_continue_transfer(const char *username, const char *passwd,
		const char *remotepath, const char *localpath,
			unsigned long dl_timeout, int tries)
{
	if (username == NULL || passwd == NULL || remotepath == NULL || localpath == NULL)
		{
			return CURL_FTP_FAIL;
		}

		char ret = CURL_FTP_SUCCESS;
		char user_pass[128];
		memset(user_pass, 0, sizeof(user_pass));
		snprintf(user_pass, sizeof(user_pass) - 1, "%s:%s", username, passwd);

		FILE       *f = NULL;
		CURL       *curlhandle = NULL;
		CURLcode   r = CURLE_GOT_NOTHING;
		curl_off_t local_file_len = -1;

		long        filesize = 0;
		int         use_resume = 0;
		struct stat file_info;


		printf("[%u] download : remotefile[%s], localfile[%s], user[%s], passwd[%s], timeout = %lu, tries_time = %d\n",
				time(0), remotepath, localpath, username, passwd, dl_timeout, tries);



		// get the file size of local file
		if (stat(localpath, &file_info) == 0)
		{
			local_file_len = file_info.st_size;
			use_resume = 1;
		}

		// open local file in append mode
		f = fopen(localpath, "ab+");
		if (f == NULL)
		{
			printf("download: open localfile[%s] failed, errmsg = [%s]!\n", localpath, strerror(errno));
			return CURL_FTP_FAIL;
		}

		// call initialization function of libcurl, both is needed
		curl_global_init(CURL_GLOBAL_ALL);
		curlhandle = curl_easy_init();

		// set the options of libcurl action
		curl_easy_setopt(curlhandle, CURLOPT_URL, remotepath);
		curl_easy_setopt(curlhandle, CURLOPT_USERPWD, user_pass);
		curl_easy_setopt(curlhandle, CURLOPT_DNS_CACHE_TIMEOUT, 3600);

		// set the maxium time of the whole download action, from curl_easy_perform, 3600s
		if (dl_timeout)
			curl_easy_setopt(curlhandle, CURLOPT_TIMEOUT, dl_timeout);
		else
			curl_easy_setopt(curlhandle, CURLOPT_TIMEOUT, 1800);

		// set the maxium time of the connection to the server, 120s, not effective if value is bigger than 60s
		curl_easy_setopt(curlhandle, CURLOPT_CONNECTTIMEOUT, 120);

		// set the maxium time of generating the ftp_response for the server, 60s, not effective
		curl_easy_setopt(curlhandle, CURLOPT_FTP_RESPONSE_TIMEOUT, 60);

		// set CURLOPT_NOPROGRESS a not-zero value to shut off the built-in progress
		curl_easy_setopt(curlhandle, CURLOPT_NOPROGRESS, 1L);


		// set the header process function
		curl_easy_setopt(curlhandle, CURLOPT_HEADERFUNCTION, getcontentlengthfunc);
		curl_easy_setopt(curlhandle, CURLOPT_HEADERDATA, &filesize);

		// set the continue transferring from breakpoint
		// in the newer version, we can set the CURLOPT_RESUME_FROM_LARGE = 0,
		// but in the older version, if we do this, curl_easy_perform will return error_no = 36
		// so we only set the CURLOPT_RESUME_FROM_LARGE when local_file_len > 0
		// curl_easy_setopt(curlhandle, CURLOPT_RESUME_FROM_LARGE, use_resume ? local_file_len : 0);
		// in some older versions, we must use CURLOPT_RESUME_FROM to replace the CURLOPT_RESUME_FROM_LARGE.
		if (use_resume && local_file_len > 0)
		{
			//curl_easy_setopt(curlhandle, CURLOPT_RESUME_FROM_LARGE, local_file_len);
			curl_easy_setopt(curlhandle, CURLOPT_RESUME_FROM, local_file_len);
		}
		else
		{
			//curl_easy_setopt(curlhandle, CURLOPT_RESUME_FROM_LARGE, 0);
			curl_easy_setopt(curlhandle, CURLOPT_RESUME_FROM, 0);
		}

		curl_easy_setopt(curlhandle, CURLOPT_WRITEFUNCTION, writefunc);
		curl_easy_setopt(curlhandle, CURLOPT_WRITEDATA, f);
		// set not-zero value to display information

		FILE *fd_log = fopen("/data/beap_gw/curl_download_continue.log", "a+");
		if (fd_log != NULL)
		{
			curl_easy_setopt(curlhandle, CURLOPT_VERBOSE, 1L);
			// set the stderr to the file pointed by fd_log
			curl_easy_setopt(curlhandle, CURLOPT_STDERR, fd_log);
		}
		else
			curl_easy_setopt(curlhandle, CURLOPT_VERBOSE, 0L);

		// set a buffer to store error messages
		char err_buf[CURL_ERROR_SIZE];
		memset(err_buf, 0, CURL_ERROR_SIZE);
		curl_easy_setopt(curlhandle, CURLOPT_ERRORBUFFER, err_buf);

		r = curl_easy_perform(curlhandle);
		if (r == CURLE_OK)
		{
			ret = CURL_FTP_SUCCESS;
		}
		else
		{
			ret = CURL_FTP_FAIL;
			printf("download: download fail(%s)\n", curl_easy_strerror(r));
		}

		fclose(f);
		curl_easy_cleanup(curlhandle);
		curl_global_cleanup();
		if (fd_log != NULL)
			fclose(fd_log);

		return ret;
}

size_t getcontentlengthfunc(void *ptr, size_t size, size_t nmemb, void *stream)
{
	int r;
	long len = 0;
	r = sscanf((const char*)ptr, "Content-Length: %ld\n", &len);
	if (r)
	{
		*((long*)stream) = len;
	}

	return size * nmemb;
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, void *stream)
{
	return fwrite(ptr, size, nmemb, (FILE*)stream);
}

#include <stdio.h>
#include <stdlib.h>

#ifndef	WIN32
#ifndef DOWNLOAD_LIBCURL
#ifndef DOWNLOAD_WGET
#ifndef NODOWNLOAD
#define NODOWNLOAD
#endif /* NODOWNLOAD */
#endif /* DOWNLOAD_WGET */
#endif /*  DOWNLOAD_LIBCURL */
#endif /* WIN32 */

#ifndef NODOWNLOAD
#ifdef WIN32
#include "common.h"
#else
#include <limits.h>
#ifdef DOWNLOAD_LIBCURL
#include <curl/curl.h>
#endif /* DOWNLOAD_LIBCURL */
#ifdef DOWNLOAD_WGET
#include "utils.h"
#include <stdlib.h>
#include <sys/wait.h>
#endif /* DOWNLOAD_WGET */
#endif
#endif /* NODOWNLOAD */

#include "downloader.h"

#ifdef DOWNLOAD_LIBCURL
static size_t WriteFileCallback(void *Contents, size_t Size, size_t nmemb, void *FileDes)
{

	FILE *fp = (FILE *)FileDes;
	fwrite(Contents, Size, nmemb, fp);
	return Size * nmemb;
	return 0;
}
#endif /* DOWNLOAD_LIBCURL */

int GetFromInternet(const char *URL, const char *File)
{
#ifndef NODOWNLOAD
#ifdef WIN32
	FILE		*fp;
	HINTERNET	webopen		=	NULL,
				webopenurl	=	NULL;
	BOOL		ReadFlag;
	DWORD		ReadedLength;
	DWORD		TotalLength = 0;
	char		Buffer[4096];
	int			ret = -1;
	int			TimeOut = 30000;

	webopen = InternetOpen("dnsforwarder", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if( webopen == NULL ){
		ret = -1 * GetLastError();
		InternetCloseHandle(webopen);
		return ret;
	}

	webopenurl = InternetOpenUrl(webopen, URL, NULL, 0, INTERNET_FLAG_RELOAD, (DWORD_PTR)NULL);
	if( webopenurl == NULL ){
		ret = -1 * GetLastError();
		InternetCloseHandle(webopenurl);
		InternetCloseHandle(webopen);
		return ret;
	}

	InternetSetOption(webopenurl, INTERNET_OPTION_CONNECT_TIMEOUT, &TimeOut, sizeof(TimeOut));

	fp = fopen(File, "wb");
	if( fp == NULL )
	{
		ret = -1 * GetLastError();
		InternetCloseHandle(webopenurl);
		InternetCloseHandle(webopen);
		return ret;
	}

	while(1)
	{
		ReadedLength = 0;
		ReadFlag = InternetReadFile(webopenurl, Buffer, sizeof(Buffer), &ReadedLength);

		if( ReadFlag == FALSE ){
			ret = -1 * GetLastError();
			InternetCloseHandle(webopenurl);
			InternetCloseHandle(webopen);
			fclose(fp);
			return ret;
		}

		if( ReadedLength == 0 )
			break;

		fwrite(Buffer, 1, ReadedLength, fp);

		TotalLength += ReadedLength;
	}

	InternetCloseHandle(webopenurl);
	InternetCloseHandle(webopen);
	fclose(fp);

	return 0;
#else /* WIN32 */

#ifdef DOWNLOAD_LIBCURL
	CURL *curl;
	CURLcode res;

	FILE *fp;

	fp = fopen(File, "w");
	if( fp == NULL )
	{
		return -1;
	}

	curl = curl_easy_init();
	if( curl == NULL )
	{
		fclose(fp);
		return -2;
	}


	curl_easy_setopt(curl, CURLOPT_URL, URL);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1l);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFileCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	res = curl_easy_perform(curl);
	if( res != CURLE_OK )
	{
		curl_easy_cleanup(curl);
		fclose(fp);
		return -3;
	} else {
		curl_easy_cleanup(curl);
		fclose(fp);
		return 0;
	}
#endif /* DOWNLOAD_LIBCURL */
#ifdef DOWNLOAD_WGET
	char Cmd[2048];

	sprintf(Cmd, "wget -t 2 -T 60 -q --no-check-certificate %s -O %s ", URL, File);

	return Execute(Cmd);
#endif /* DOWNLOAD_WGET */
#endif /* WIN32 */
#else /* NODOWNLOAD */
	return -1;
#endif /* NODOWNLOAD */
}

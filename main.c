#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h> /* exit() */
#include <ctype.h> /* isspace() */

#ifndef NODOWNLOAD
	#ifndef WIN32
		#include <sys/types.h>
		#include <sys/stat.h>
		#ifdef DOWNLOAD_LIBCURL
			#include <curl/curl.h>
		#endif /* DOWNLOAD_LIBCURL */
	#endif /* WIN32 */
#endif /* NODOWNLOAD */

#include "dnsrelated.h"
#include "common.h"
#include "utils.h"
#include "readconfig.h"
#include "querydnsinterface.h"
#include "request_response.h"
#include "debug.h"

#define VERSION__ "5.0.40"

#define PRINTM(...)		if(ShowMassages == TRUE) printf(__VA_ARGS__);

static char		*ConfigFile;
static BOOL		DeamonMode;

int DaemonInit(void)
{
#ifdef WIN32
	char		*CmdLine = GetCommandLine();
	char		ModuleName[320];
	char		*itr;
	char		*NewArguments;

	int			ModuleNameLength;

	BOOL		StartUpStatus;
	STARTUPINFO	StartUpInfo;
	PROCESS_INFORMATION ProcessInfo;

	ModuleNameLength = GetModuleFileName(NULL, ModuleName, sizeof(ModuleName) - 1);

	if( ModuleNameLength == 0 )
	{
		return 1;
	} else {
		ModuleName[sizeof(ModuleName) - 1] = '\0';
	}

	for(; isspace(*CmdLine); ++CmdLine);
	if(*CmdLine == '"')
	{
		itr	=	strchr(++CmdLine, '"');
	} else {
		itr	=	strchr(CmdLine, ' ');
	}

	if( itr != NULL )
		CmdLine = itr + 1;
	else
		return 1;

	for(; isspace(*CmdLine); ++CmdLine);

	NewArguments = SafeMalloc(strlen(ModuleName) + strlen(CmdLine) + 32);
	strcpy(NewArguments, "\"");
	strcat(NewArguments, ModuleName);
	strcat(NewArguments, "\" ");
	strcat(NewArguments, CmdLine);

	itr = strstr(NewArguments + strlen(ModuleName) + 2, "-d");
	while( itr != NULL )
	{
		*(itr + 1) = 'q';
		itr = strstr(itr + 2, "-d");
	}

	StartUpInfo.cb = sizeof(StartUpInfo);
	StartUpInfo.lpReserved = NULL;
	StartUpInfo.lpDesktop = NULL;
	StartUpInfo.lpTitle = NULL;
	StartUpInfo.dwFlags = STARTF_USESHOWWINDOW;
	StartUpInfo.wShowWindow = SW_HIDE;
	StartUpInfo.cbReserved2 = 0;
	StartUpInfo.lpReserved2 = NULL;

	StartUpStatus = CreateProcess(NULL, NewArguments, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &StartUpInfo, &ProcessInfo);

	SafeFree(NewArguments);
	if( StartUpStatus != FALSE )
	{
		printf("deamon process pid : %d\n", (int)(ProcessInfo.dwProcessId));
		exit(0);
	} else {
		return 1;
	}
#else /* WIN32 */

    pid_t	pid;
    if( (pid = fork()) < 0 )
    {
        return 1;
    }
    else
    {
        if(pid != 0)
        {
            printf("deamon process pid : %d\n", pid);
            exit(0);
        }
        setsid();
        umask(0); /* clear file mode creation mask */
        close(0);
        close(1);
        close(2);
        return 0;
    }
#endif /* WIN32 */
}

int GetDefaultConfigureFile(char *out, int OutLength)
{
#ifdef WIN32
	GetModulePath(out, OutLength);
	strcat(out, "\\dnsforwarder.config");
#else
	GetConfigDirectory(out);
	strcat(out, "/config");
#endif
	return 0;
}

#ifndef WIN32
void PrepareEnvironment(void)
{
	char ConfigDirectory[2048];

	GetConfigDirectory(ConfigDirectory);

	if( mkdir(ConfigDirectory, S_IRWXU | S_IRGRP | S_IROTH) != 0 )
	{
		int		ErrorNum = GET_LAST_ERROR();
		char	ErrorMessage[320];
		ErrorMessage[0] = '\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

		printf("mkdir : %s failed : %s\n", ConfigDirectory, ErrorMessage);
	}

	printf("Please put configure file into `%s' and rename it to `config'.\n", ConfigDirectory);
}
#endif

int ArgParse(int argc, char *argv_ori[], const char **Contexts)
{
	char **argv = argv_ori;
	++argv;
	*Contexts = NULL;
    while(*argv != NULL)
    {
    	if(strcmp("-h", *argv) == 0)
		{
			printf("DNSforwarder by several people. Version "VERSION__" . License : GPL v3.\n Time of compilation : %s %s.\n\n", __DATE__, __TIME__);
			printf("https://github.com/holmium/dnsforwarder\n\n");
			printf("Usage : %s [args].\n", strrchr(argv_ori[0], PATH_SLASH_CH) == NULL ? argv_ori[0] : strrchr(argv_ori[0], PATH_SLASH_CH) + 1);
			printf(" [args] is case sensitivity and can be zero or more (in any order) of:\n"
				  "  -f <FILE>  Use configuration <FILE> instead of the default one.\n"
				  "  -q         Quiet mode. Do not print any information.\n"
				  "  -e         Show only error messages.\n"
				  "  -d         Daemon mode. Running at background.\n"
#ifndef WIN32
				  "\n"
				  "  -p         Prepare needed environment.\n"
#endif
				  "\n"
				  "  -h         Show this help.\n"
				  "\n"
				  "Output format:\n"
				  " Date & Time [Udp|Tcp|Cache|Hosts|Refused|Blocked][Client IP][Queried type][Queried domain] : Message size\n"
				  "    Results\n"
				  );
			exit(0);
		}
        if(strcmp("-q", *argv) == 0)
        {
            ShowMassages = FALSE;
            ErrorMessages = FALSE;
            ++argv;
            continue;
        }

        if(strcmp("-e", *argv) == 0)
        {
            ShowMassages = FALSE;
            ++argv;
            continue;
        }

        if(strcmp("-d", *argv) == 0)
        {
			DeamonMode = TRUE;
            ++argv;
            continue;
        }

        if(strcmp("-f", *argv) == 0)
        {
            ConfigFile = *(++argv);
            ++argv;
            continue;
        }

#ifndef WIN32
		if( strcmp("-p", *argv) == 0 )
		{
			PrepareEnvironment();
			exit(0);

			++argv;
            continue;
		}
#endif

		if( strcmp("-CONTEXT", *argv) == 0 )
		{
			*Contexts = *(++argv);
			++argv;
			continue;
		}

		PRINTM("Unrecognisable arg `%s'. Try `-h'.\n", *argv);
        ++argv;
    }

    return 0;
}

int main(int argc, char *argv[])
{
#ifdef WIN32
    WSADATA wdata;
#endif
	const char *Contexts = NULL;

#ifndef NODOWNLOAD
#ifdef WIN32
    if(WSAStartup(MAKEWORD(2, 2), &wdata) != 0)
        return -1;
#else
#ifdef DOWNLOAD_LIBCURL
	curl_global_init(CURL_GLOBAL_ALL);
#endif /* DOWNLOAD_LIBCURL */
#endif /* WIN32 */
#endif /* NODOWNLOAD */

#ifdef WIN32
	SetConsoleTitle("dnsforwarder");
#endif /* WIN32 */

	ArgParse(argc, argv, &Contexts);

	if( ConfigFile == NULL )
	{
		ConfigFile = malloc(320);
		if( ConfigFile == NULL )
		{
			return -1;
		}

		GetDefaultConfigureFile(ConfigFile, 320);

	}

    PRINTM("DNSforwarder mainly by holmium. Version "VERSION__" . License : GPL v3.\nTime of compilation : %s %s.\n\n", __DATE__, __TIME__);

#ifndef WIN32
    PRINTM("Please run `dnsforwarder -p' if something goes wrong.\n\n")
#endif

    PRINTM("Configure File : %s\n\n", ConfigFile);

	if( DeamonMode == TRUE )
	{
		if( DaemonInit() == 0 )
		{
			ShowMassages = FALSE;
			ErrorMessages = FALSE;
		} else {
			printf("Daemon init failed, continuing on non-daemon mode.\n");
		}
	}

	if( QueryDNSInterfaceInit(ConfigFile, Contexts) != 0 )
		goto JustEnd;

	putchar('\n');

	if( QueryDNSInterfaceStart() != 0 )
		goto JustEnd;

	QueryDNSInterfaceWait();

JustEnd:
#ifdef WIN32
    WSACleanup();
#endif
    return 0;
}

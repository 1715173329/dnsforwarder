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
#include "logs.h"
#include "mmgr.h"
#include "udpfrontend.h"

#define VERSION__ "6.0.0"

static char		*ConfigFile;
static BOOL		DeamonMode;

static BOOL     ShowMessages = TRUE;
static BOOL     ShowDebug = FALSE;

static ConfigFileInfo	ConfigInfo;

int EnvironmentInit(char *ConfigFile, const char *Contexts)
{
	VType	TmpTypeDescriptor;
	char	TmpStr[1024];

	GetFileDirectory(TmpStr);
	strcat(TmpStr, PATH_SLASH_STR);

	SetProgramEnvironment("PROGRAMDIRECTORY", TmpStr);

	ConfigInitInfo(&ConfigInfo, Contexts);

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "LogOn", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 102400;
    ConfigAddOption(&ConfigInfo, "LogFileThresholdLength", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

	GetFileDirectory(TmpStr);
	strcat(TmpStr, PATH_SLASH_STR);
    TmpTypeDescriptor.str = TmpStr;
    ConfigAddOption(&ConfigInfo, "LogFileFolder", STRATEGY_REPLACE, TYPE_PATH, TmpTypeDescriptor, NULL);

    /*
    TmpTypeDescriptor.str = "127.0.0.1";
    ConfigAddOption(&ConfigInfo, "LocalInterface", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, "Local working interface");
    */

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "UDPLocal", STRATEGY_APPEND_DISCARD_DEFAULT, TYPE_STRING, TmpTypeDescriptor, "Local working interfaces");
    ConfigSetStringDelimiters(&ConfigInfo, "UDPLocal", ",");
    TmpTypeDescriptor.str = "127.0.0.1";
    ConfigSetValue(&ConfigInfo, TmpTypeDescriptor, "UDPLocal");

    TmpTypeDescriptor.INT32 = 53;
    ConfigAddOption(&ConfigInfo, "LocalPort", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, "Local working port");

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "OpenLocalTCP", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, "Local TCP is opened");


    TmpTypeDescriptor.str = "TCP";
    ConfigAddOption(&ConfigInfo, "PrimaryServer", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, "Primary server");

    TmpTypeDescriptor.str = "8.8.8.8";
    ConfigAddOption(&ConfigInfo, "TCPServer", STRATEGY_APPEND_DISCARD_DEFAULT, TYPE_STRING, TmpTypeDescriptor, "TCP Server");

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "TCPProxy", STRATEGY_APPEND_DISCARD_DEFAULT, TYPE_STRING, TmpTypeDescriptor, NULL);

    /*
    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "UDPServer", STRATEGY_APPEND_DISCARD_DEFAULT, TYPE_STRING, TmpTypeDescriptor, "UDP Server");
    */

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "UDPGroup", STRATEGY_APPEND_DISCARD_DEFAULT, TYPE_STRING, TmpTypeDescriptor, "UDP Groups");
    ConfigSetStringDelimiters(&ConfigInfo, "UDPGroup", "\t ");
    TmpTypeDescriptor.str = "1.2.4.8,114.114.114.114 * on";
    ConfigSetValue(&ConfigInfo, TmpTypeDescriptor, "UDPGroup");

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "ParallelQuery", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, "UDP Parallel Query");

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "ExcludedDomain", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "AlwaysTCP", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "AlwaysUDP", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "ExcludedList", STRATEGY_APPEND, TYPE_PATH, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "UDPBlock_IP", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "IPSubstituting", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "DedicatedServer", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);


    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "DomainStatistic", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);

	GetFileDirectory(TmpStr);
	strcat(TmpStr, PATH_SLASH_STR);
	strcat(TmpStr, "StatisticTemplate.html");
    TmpTypeDescriptor.str = TmpStr;
    ConfigAddOption(&ConfigInfo, "DomainStatisticTempletFile", STRATEGY_REPLACE, TYPE_PATH, TmpTypeDescriptor, NULL);

	TmpTypeDescriptor.str = "<!-- INSERT HERE -->";
	ConfigAddOption(&ConfigInfo, "StatisticInsertionPosition", STRATEGY_DEFAULT, TYPE_STRING, TmpTypeDescriptor, NULL);

	TmpTypeDescriptor.INT32 = 60;
	ConfigAddOption(&ConfigInfo, "StatisticUpdateInterval", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "Hosts", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, "Hosts File");

    TmpTypeDescriptor.INT32 = 18000;
    ConfigAddOption(&ConfigInfo, "HostsUpdateInterval", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 30;
    ConfigAddOption(&ConfigInfo, "HostsRetryInterval", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

	GetFileDirectory(TmpStr);
	strcat(TmpStr, PATH_SLASH_STR);
	strcat(TmpStr, "hosts.txt");
    TmpTypeDescriptor.str = TmpStr;
    ConfigAddOption(&ConfigInfo, "HostsDownloadPath", STRATEGY_REPLACE, TYPE_PATH, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "HostsScript", STRATEGY_REPLACE, TYPE_PATH, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "BlockIpv6WhenIpv4Exists", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "AppendHosts", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

	ConfigAddAlias(&ConfigInfo, "address", "AppendHosts");


	TmpTypeDescriptor.boolean = TRUE;
    ConfigAddOption(&ConfigInfo, "UseCache", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, "Use cache");

    TmpTypeDescriptor.INT32 = 1048576;
    ConfigAddOption(&ConfigInfo, "CacheSize", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.boolean = TRUE;
    ConfigAddOption(&ConfigInfo, "MemoryCache", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, "Memory Cache");

	GetFileDirectory(TmpStr);
	strcat(TmpStr, PATH_SLASH_STR);
	strcat(TmpStr, "cache");
    TmpTypeDescriptor.str = TmpStr;
    ConfigAddOption(&ConfigInfo, "CacheFile", STRATEGY_REPLACE, TYPE_PATH, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "IgnoreTTL", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, "Ignore TTL");

    TmpTypeDescriptor.INT32 = -1;
    ConfigAddOption(&ConfigInfo, "OverrideTTL", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 1;
    ConfigAddOption(&ConfigInfo, "MultipleTTL", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "CacheControl", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

	TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "ReloadCache", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);

	TmpTypeDescriptor.boolean = FALSE;
	ConfigAddOption(&ConfigInfo, "OverwriteCache", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);



    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "DisabledType", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "DisabledDomain", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "DisabledList", STRATEGY_APPEND, TYPE_PATH, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 0;
    ConfigAddOption(&ConfigInfo, "RefusingResponseCode", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "CheckIP", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "GoodIPList", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "GoodIPListAddIP", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

	if( ConfigOpenFile(&ConfigInfo, ConfigFile) == 0 )
	{
		ConfigRead(&ConfigInfo);
		ConfigCloseFile(&ConfigInfo);
		return 0;
	} else {
		ERRORMSG("WARNING: Cannot load configuration file : %s, using default options. Or use `-f' to specify other configure file.\n", ConfigFile);
		return 0;
	}
}

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
				  "  -D         Show debug messages.\n"
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
            ShowMessages = FALSE;
            ++argv;
            continue;
        }

        if(strcmp("-D", *argv) == 0)
        {
			ShowDebug = TRUE;
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

		printf("Unrecognisable arg `%s'. Try `-h'.\n", *argv);
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
    if( WSAStartup(MAKEWORD(2, 2), &wdata) != 0 )
    {
        return -244;
    }
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
			return -264;
		}

		GetDefaultConfigureFile(ConfigFile, 320);
	}

    printf("DNSforwarder mainly by holmium. Version "VERSION__" . License : GPL v3.\nTime of compilation : %s %s.\n\n", __DATE__, __TIME__);

#ifndef WIN32
    printf("Please run `dnsforwarder -p' if something goes wrong.\n\n")
#endif

    printf("Configure File : %s\n\n", ConfigFile);

	if( DeamonMode )
	{
		if( DaemonInit() == 0 )
		{
			ShowMessages = FALSE;
		} else {
			printf("Daemon init failed, continuing on non-daemon mode.\n");
		}
	}

	if( EnvironmentInit(ConfigFile, Contexts) != 0 )
    {
        return -498;
    }

	if( Log_Init(&ConfigInfo, ShowMessages, ShowDebug) != 0 )
    {
        return -291;
    }

    if( MMgr_Init(&ConfigInfo) != 0 )
    {
        return -305;
    }

    if( UdpFrontend_Init(&ConfigInfo) != 0 )
    {
        return -311;
    }

	putchar('\n');

#ifdef WIN32
    WSACleanup();
#endif
    return 0;
}

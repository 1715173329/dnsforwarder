#include <string.h>
#include "common.h"
#include "querydnsinterface.h"
#include "querydnsbase.h"
#include "querydnslistentcp.h"
#include "querydnslistenudp.h"
#include "request_response.h"
#include "readconfig.h"
#include "hosts.h"
#include "excludedlist.h"
#include "gfwlist.h"
#include "utils.h"
#include "domainstatistic.h"
#include "debug.h"

static ConfigFileInfo	ConfigInfo;

int QueryDNSInterfaceInit(char *ConfigFile)
{
	VType	TmpTypeDescriptor;
	char	TmpStr[1024];

	GetFileDirectory(TmpStr);
	strcat(TmpStr, PATH_SLASH_STR);

	SetProgramEnvironment("PROGRAMDIRECTORY", TmpStr);

	ConfigInitInfo(&ConfigInfo);

    TmpTypeDescriptor.str = "127.0.0.1";
    ConfigAddOption(&ConfigInfo, "LocalInterface", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, "Local working interface");

    TmpTypeDescriptor.INT32 = 53;
    ConfigAddOption(&ConfigInfo, "LocalPort", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, "Local working port");

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "OpenLocalTCP", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, "Local TCP is opened");


    TmpTypeDescriptor.str = "TCP";
    ConfigAddOption(&ConfigInfo, "PrimaryServer", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, "Primary server");

    TmpTypeDescriptor.str = "8.8.8.8";
    ConfigAddOption(&ConfigInfo, "TCPServer", STRATEGY_APPEND_DISCARD_DEFAULT, TYPE_STRING, TmpTypeDescriptor, "TCP Server");

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "UDPServer", STRATEGY_APPEND_DISCARD_DEFAULT, TYPE_STRING, TmpTypeDescriptor, "UDP Server");

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "ParallelQuery", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, "UDP Parallel Query");

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "ExcludedDomain", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "ExcludedList", STRATEGY_APPEND, TYPE_PATH, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "UDPAntiPollution", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, "UDP Anti-pollution");

    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "UDPAppendEDNSOpt", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "UDPBlock_IP", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "IPSubstituting", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "DedicatedServer", STRATEGY_APPEND, TYPE_STRING, TmpTypeDescriptor, NULL);


    TmpTypeDescriptor.boolean = FALSE;
    ConfigAddOption(&ConfigInfo, "DomainStatistic", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 60;
    ConfigAddOption(&ConfigInfo, "StatisticUpdateInterval", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);


    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "Hosts", STRATEGY_REPLACE, TYPE_PATH, TmpTypeDescriptor, "Hosts File");

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


    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "GfwList", STRATEGY_REPLACE, TYPE_STRING, TmpTypeDescriptor, "GFW List");

    TmpTypeDescriptor.boolean = TRUE;
    ConfigAddOption(&ConfigInfo, "GfwListBase64Decode", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 21600;
    ConfigAddOption(&ConfigInfo, "GfwListUpdateInterval", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.INT32 = 30;
    ConfigAddOption(&ConfigInfo, "GfwListRetryInterval", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

	GetFileDirectory(TmpStr);
	strcat(TmpStr, PATH_SLASH_STR);
	strcat(TmpStr, "gfwlist.txt");
    TmpTypeDescriptor.str = TmpStr;
    ConfigAddOption(&ConfigInfo, "GfwListDownloadPath", STRATEGY_REPLACE, TYPE_PATH, TmpTypeDescriptor, NULL);


    TmpTypeDescriptor.INT32 = 0;
    ConfigAddOption(&ConfigInfo, "RefusingResponseCode", STRATEGY_DEFAULT, TYPE_INT32, TmpTypeDescriptor, NULL);

	if( ConfigOpenFile(&ConfigInfo, ConfigFile) == 0 )
	{
		ConfigRead(&ConfigInfo);
		ConfigCloseFile(&ConfigInfo);
		return 0;
	} else {
		ERRORMSG("WARNING: Cannot load configuration file : %s, use default options. Use `-f' to specify another configure file.\n", ConfigFile);
		return 0;
	}
}

static int GetPrimaryProtocol(void)
{
	const char *PrimaryProtocol_Ori = ConfigGetRawString(&ConfigInfo, "PrimaryServer");
	char	PrimaryProtocol[8];

	strncpy(PrimaryProtocol, PrimaryProtocol_Ori, 5);

	StrToLower(PrimaryProtocol);

	if( strncmp(PrimaryProtocol, "tcp", 3) == 0 )
	{
		return DNS_QUARY_PROTOCOL_TCP;
	} else if( strncmp(PrimaryProtocol, "udp", 3) == 0 ) {
		return DNS_QUARY_PROTOCOL_UDP;
	} else {
		ERRORMSG("PrimaryServer `%s' may not a good idea.\n", PrimaryProtocol_Ori);
		return -1;
	}
}

int QueryDNSInterfaceStart(void)
{
	const char	*LocalAddr = ConfigGetRawString(&ConfigInfo, "LocalInterface");
	int			LocalPort = ConfigGetInt32(&ConfigInfo, "LocalPort");
	int			PrimaryProtocol = GetPrimaryProtocol();

	int			IsZeroZeroZeroZero;

	if( ShowMassages == TRUE )
	{
		ConfigDisplay(&ConfigInfo);
		putchar('\n');
	}

	if( PrimaryProtocol < 0 )
	{
		return -1;
	}

	srand(time(NULL));

	ExcludedList_Init(&ConfigInfo);
	GfwList_Init(&ConfigInfo, FALSE);

	InitAddress(&ConfigInfo);

	if( InternalInterface_Init(PrimaryProtocol, LocalAddr, LocalPort) != 0 )
	{
		ERRORMSG("Address %s:%d may not a good idea.\n", LocalAddr, LocalPort);
		return -1;
	}

	DynamicHosts_Init(&ConfigInfo);

	if( ConfigGetBoolean(&ConfigInfo, "DomainStatistic") == TRUE )
	{
		DomainStatistic_Init(ConfigGetInt32(&ConfigInfo, "StatisticUpdateInterval"));
	}

	if( QueryDNSListenUDPInit(&ConfigInfo) != 0 )
	{
		return -1;
	}

	QueryDNSListenUDPStart();

	if( ConfigGetBoolean(&ConfigInfo, "OpenLocalTCP") == TRUE )
	{
		if( QueryDNSListenTCPInit(&ConfigInfo) != 0 )
		{
			return -1;
		}

		QueryDNSListenTCPStart();
	}

	if( ConfigGetBoolean(&ConfigInfo, "UseCache") == TRUE )
	{
		DNSCache_Init(&ConfigInfo);
	}

	if( ConfigGetBoolean(&ConfigInfo, "UDPAntiPollution") == TRUE )
	{
		SetUDPAntiPollution(TRUE);
		SetUDPAppendEDNSOpt(ConfigGetBoolean(&ConfigInfo, "UDPAppendEDNSOpt"));

		InitBlockedIP(ConfigGetStringList(&ConfigInfo, "UDPBlock_IP"));
		InitIPSubstituting(ConfigGetStringList(&ConfigInfo, "IPSubstituting"));
	}

	TransferStart(TRUE);

	DynamicHosts_Start(&ConfigInfo);

	GfwList_PeriodicWork(&ConfigInfo);

	IsZeroZeroZeroZero = !strncmp(LocalAddr, "0.0.0.0", 7);
	INFO("Now you can set DNS%s%s.\n", IsZeroZeroZeroZero ? "" : " to ", IsZeroZeroZeroZero ? "" : LocalAddr);

	return 0;
}

void QueryDNSInterfaceWait(void)
{
#ifdef WIN32
	ThreadHandle CurrentThread = GetCurrentThread();
#endif /* WIN32 */

	if( ConfigGetBoolean(&ConfigInfo, "DomainStatistic") == TRUE )
	{
		DomainStatistic_Hold();
	} else {
		while(TRUE)
		{
#ifdef WIN32
			SuspendThread(CurrentThread);
#else /* WIN32 */
			pause();
#endif /* WIN32 */
		}
	}

#ifdef WIN32
	CloseHandle(CurrentThread);
#endif /* WIN32 */
}

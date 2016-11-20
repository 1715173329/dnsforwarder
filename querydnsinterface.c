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
#include "utils.h"
#include "domainstatistic.h"
#include "goodiplist.h"
#include "debug.h"

static ConfigFileInfo	ConfigInfo;

int QueryDNSInterfaceInit(char *ConfigFile, const char *Contexts)
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
    ConfigAddOption(&ConfigInfo, "TCPProxy", STRATEGY_APPEND_DISCARD_DEFAULT, TYPE_STRING, TmpTypeDescriptor, NULL);

    TmpTypeDescriptor.str = NULL;
    ConfigAddOption(&ConfigInfo, "UDPServer", STRATEGY_APPEND_DISCARD_DEFAULT, TYPE_STRING, TmpTypeDescriptor, "UDP Server");

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
    ConfigAddOption(&ConfigInfo, "DisableIpv6WhenIpv4Exists", STRATEGY_DEFAULT, TYPE_BOOLEAN, TmpTypeDescriptor, NULL);

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

static DNSQuaryProtocol GetPrimaryProtocol(const char *FirstSet)
{
	static DNSQuaryProtocol PrimaryProtocol = DNS_QUARY_PROTOCOL_UNSPECIFIED;

	if( PrimaryProtocol == DNS_QUARY_PROTOCOL_UNSPECIFIED )
	{
		char	PrimaryProtocol_Str[8];

		strncpy(PrimaryProtocol_Str, FirstSet, 5);

		StrToLower(PrimaryProtocol_Str);

		if( strncmp(PrimaryProtocol_Str, "tcp", 3) == 0 )
		{
			PrimaryProtocol =  DNS_QUARY_PROTOCOL_TCP;
		} else if( strncmp(PrimaryProtocol_Str, "udp", 3) == 0 ) {
			PrimaryProtocol =  DNS_QUARY_PROTOCOL_UDP;
		} else {
			ERRORMSG("PrimaryServer `%s' may not be a good idea.\n", FirstSet);
			PrimaryProtocol = DNS_QUARY_PROTOCOL_UNSPECIFIED;
		}
	}

	return PrimaryProtocol;
}

int QueryDNSInterfaceStart(void)
{
	const char	*LocalAddr = ConfigGetRawString(&ConfigInfo, "LocalInterface");
	int			LocalPort = ConfigGetInt32(&ConfigInfo, "LocalPort");
	DNSQuaryProtocol PrimaryProtocol = GetPrimaryProtocol(ConfigGetRawString(&ConfigInfo, "PrimaryServer"));

	int			IsZeroZeroZeroZero;

	Debug_Init(&ConfigInfo);

	if( PrimaryProtocol == DNS_QUARY_PROTOCOL_UNSPECIFIED )
	{
		return -1;
	}

	if( ShowMessages == TRUE )
	{
		ConfigDisplay(&ConfigInfo);
		putchar('\n');
	}

	srand(time(NULL));

	ExcludedList_Init(&ConfigInfo, PrimaryProtocol);

	InitAddress(&ConfigInfo);

	TCPProxies_Init(ConfigGetStringList(&ConfigInfo, "TCPProxy"));

	if( InternalInterface_Init(PrimaryProtocol, LocalAddr, LocalPort) != 0 )
	{
		ERRORMSG("Address %s:%d may not a good idea.\n", LocalAddr, LocalPort);
		return -1;
	}

	GoodIpList_Init(&ConfigInfo);
	DynamicHosts_Init(&ConfigInfo);

	if( ConfigGetBoolean(&ConfigInfo, "DomainStatistic") == TRUE )
	{
		DomainStatistic_Init(&ConfigInfo);
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

    InitBlockedIP(ConfigGetStringList(&ConfigInfo, "UDPBlock_IP"));
    InitIPSubstituting(ConfigGetStringList(&ConfigInfo, "IPSubstituting"));

	TransferStart(TRUE);

	DynamicHosts_Start(&ConfigInfo);

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
	}

	while(TRUE)
	{
#ifdef WIN32
		SuspendThread(CurrentThread);
#else /* WIN32 */
		pause();
#endif /* WIN32 */
	}

#ifdef WIN32
	CloseHandle(CurrentThread);
#endif /* WIN32 */
}

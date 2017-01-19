#include "hosts.h"
#include "addresslist.h"
#include "udpfrontend.h"
#include "hcontext.h"
#include "socketpuller.h"
#include "goodiplist.h"
#include "logs.h"

static BOOL BlockIpv6WhenIpv4Exists = FALSE;

static SOCKET	IncomeSocket;
static Address_Type	IncomeAddress;

static SOCKET TryBindLocal(BOOL Ipv6, int StartPort, Address_Type *Address)
{
    const char *Loopback = Ipv6 ? "[::1]" : "127.0.0.1";

	int MaxTime = 10000;

	Address_Type Address1;
	SOCKET ret = INVALID_SOCKET;

	do {
		AddressList_ConvertToAddressFromString(&Address1, Loopback, StartPort);

		ret = socket(Address1.family, SOCK_DGRAM, IPPROTO_UDP);
		if( ret == INVALID_SOCKET )
        {
            continue;
        }

        if( bind(ret,
                 (struct sockaddr *)&(Address1.Addr),
                 GetAddressLength(Address1.family)
                 )
           != 0 )
        {
            CLOSE_SOCKET(ret);
            ret = INVALID_SOCKET;
            continue;
        }

	} while( ret == INVALID_SOCKET && --MaxTime > 0 && ++StartPort > 0 );

	if( ret != INVALID_SOCKET && Address != NULL )
    {
        memcpy(Address, &Address1, sizeof(Address_Type));
    }

	return ret;
}

BOOL Hosts_TypeExisting(const char *Domain, HostsRecordType Type)
{
    return StaticHosts_TypeExisting(Domain, Type) ||
           DynamicHosts_TypeExisting(Domain, Type);
}

static HostsUtilsTryResult Hosts_Try_Inner(IHeader *Header, int BufferLength)
{
    HostsUtilsTryResult ret;

    ret = StaticHosts_Try(Header, BufferLength);
    if( ret != HOSTSUTILS_TRY_NONE )
    {
        return ret;
    }

    return DynamicHosts_Try(Header, BufferLength);
}

static int Hosts_GetCName(const char *Domain, char *Buffer)
{
    return !(StaticHosts_GetCName(Domain, Buffer) == 0 ||
           DynamicHosts_GetCName(Domain, Buffer) == 0);
}

HostsUtilsTryResult Hosts_Try(IHeader *Header, int BufferLength)
{
    HostsUtilsTryResult ret;

    if( BlockIpv6WhenIpv4Exists )
    {
        if( Header->Type == DNS_TYPE_AAAA &&
            (Hosts_TypeExisting(Header->Domain, HOSTS_TYPE_A) ||
             Hosts_TypeExisting(Header->Domain, HOSTS_TYPE_GOOD_IP_LIST)
             )
            )
        {
            /** TODO: Show blocked message */
            return HOSTSUTILS_TRY_BLOCKED;
        }
    }

    ret = Hosts_Try_Inner(Header, BufferLength);

    if( ret == HOSTSUTILS_TRY_RECURSED )
    {
        if( sendto(IncomeSocket,
                   (const char *)Header, /* Only send header */
                   sizeof(IHeader), /* Only send header */
                   MSG_NOSIGNAL,
                   (const struct sockaddr *)&(IncomeAddress.Addr),
                   GetAddressLength(IncomeAddress.family)
                   )
            < 0 )
        {
            return HOSTSUTILS_TRY_NONE;
        }
    }

    return ret;
}

int Hosts_Get(IHeader *Header, int BufferLength)
{
    switch( Hosts_Try(Header, BufferLength) )
    {
    case HOSTSUTILS_TRY_BLOCKED:
        IHeader_SendBackRefusedMessage(Header);
        ShowRefusingMessage(Header, "Disabled because of existing IPv4 host");
        return 0;
        break;

    case HOSTSUTILS_TRY_NONE:
        return -126;
        break;

    case HOSTSUTILS_TRY_RECURSED:
        /** TODO: Show hosts message */
        return 0;

    case HOSTSUTILS_TRY_OK:
        ShowNormalMessage(Header, 'H');
        return 0;
        break;

    default:
        return -139;
        break;
    }
}

static int Hosts_SocketLoop(void *Unused)
{
	static HostsContext	Context;
	static SocketPuller Puller;

    static SOCKET	OutcomeSocket;
    static Address_Type	OutcomeAddress;

	static const struct timeval	LongTime = {3600, 0};
	static const struct timeval	ShortTime = {10, 0};

	struct timeval	TimeLimit = LongTime;

	#define LEFT_LENGTH_SL (sizeof(RequestBuffer) - sizeof(IHeader))
	static char		RequestBuffer[2048];
	IHeader         *Header = (IHeader *)RequestBuffer;
	char		    *RequestEntity = RequestBuffer + sizeof(IHeader);

	OutcomeSocket = TryBindLocal(Ipv6_Aviliable(), 10300, &OutcomeAddress);

	if( OutcomeSocket == INVALID_SOCKET )
	{
		return -416;
	}

    if( SocketPuller_Init(&Puller) != 0 )
    {
        return -423;
    }

    Puller.Add(&Puller, IncomeSocket, NULL, 0);
    Puller.Add(&Puller, OutcomeSocket, NULL, 0);

    if( HostsContext_Init(&Context) != 0 )
    {
        return -431;
    }

    srand(time(NULL));

	while( TRUE )
	{
	    SOCKET  Pulled;

	    Pulled = Puller.Select(&Puller, &TimeLimit, NULL, TRUE, FALSE);
	    if( Pulled == INVALID_SOCKET )
        {
            TimeLimit = LongTime;
            Context.Swep(&Context);
        } else if( Pulled == IncomeSocket )
        {
            /* Recursive query */
            int State;
            char RecursedDomain[DOMAIN_NAME_LENGTH_MAX + 1];
            uint16_t NewIdentifier;

            TimeLimit = ShortTime;

            State = recvfrom(IncomeSocket,
                             RequestBuffer, /* Receiving a header */
                             sizeof(RequestBuffer),
                             0,
                             NULL,
                             NULL
                             );

            if( State < 1 )
            {
                continue;
            }

            if( Hosts_GetCName(Header->Domain, RecursedDomain) != 0 )
            {
                /** TODO: Show fatal error */
                continue;
            }

            NewIdentifier = rand();

            if( Context.Add(&Context, Header, RecursedDomain, NewIdentifier)
                != 0 )
            {
                /** TODO: Show fatal error */
                continue;
            }

            if( HostsUtils_Query(OutcomeSocket,
                                 &OutcomeAddress,
                                 NewIdentifier,
                                 RecursedDomain,
                                 Header->Type
                                 )
                != 0 )
            {
                /** TODO: Show an error */
                continue;
            }

        } else if( Pulled == OutcomeSocket )
        {
            int State;

            #define LEFT_LENGTH_SL_N (sizeof(NewRequest) - sizeof(IHeader));
            static char NewRequest[2048];
            IHeader *NewHeader = (IHeader *)NewRequest;

            TimeLimit = ShortTime;

            State = recvfrom(OutcomeSocket,
                             RequestEntity,
                             LEFT_LENGTH_SL,
                             0,
                             NULL,
                             NULL
                             );

            if( State < 1 )
            {
                continue;
            }

            IHeader_Fill(Header,
                         FALSE,
                         RequestEntity,
                         State,
                         NULL,
                         INVALID_SOCKET,
                         AF_UNSPEC,
                         ""
                         );

            if( Context.FindAndRemove(&Context, Header, NewHeader) != 0 )
            {
                /** TODO: Show an error */
                continue;
            }

            if( HostsUtils_CombineRecursedResponse(NewRequest,
                                                   sizeof(NewRequest),
                                                   RequestEntity,
                                                   State,
                                                   Header->Domain
                                                   )
                != 0 )
            {
                /** TODO: Show fatal error */
                continue;
            }

            if( IHeader_SendBack(NewHeader) != 0 )
            {
                /** TODO: Show an error */
                continue;
            }

            ShowNormalMessage(NewHeader, 'H');
        } else {}
	}

	return 0;
}

int Hosts_Init(ConfigFileInfo *ConfigInfo)
{
    ThreadHandle t;

    StaticHosts_Init(ConfigInfo);
    DynamicHosts_Init(ConfigInfo);

    GoodIpList_Init(ConfigInfo);

    BlockIpv6WhenIpv4Exists = ConfigGetBoolean(ConfigInfo,
                                                 "BlockIpv6WhenIpv4Exists"
                                                 );

    IncomeSocket = TryBindLocal(Ipv6_Aviliable(), 10200, &IncomeAddress);
    if( IncomeSocket == INVALID_SOCKET )
    {
        return -25;
    }

    CREATE_THREAD(Hosts_SocketLoop, NULL, t);
    DETACH_THREAD(t);

    return 0;
}

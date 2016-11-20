#include "request_response.h"
#include "domainstatistic.h"
#include "dnsparser.h"
#include "dnsgenerator.h"
#include "dnscache.h"
#include "addresschunk.h"
#include "ipmisc.h"
#include "internalsocket.h"
#include "socketpool.h"
#include "checkip.h"
#include "utils.h"
#include "common.h"

static AddressChunk	Addresses;
static BOOL			ParallelQuery;

static sa_family_t	UDPParallelMainFamily = AF_UNSPEC;
static struct sockaddr **UDPAddresses_Array = NULL;
static sa_family_t	*TCPParallelFamilies = NULL;
static struct sockaddr **TCPAddresses_Array = NULL;

static int LoadDedicatedServer(ConfigFileInfo *ConfigInfo)
{
	StringList    *DedicatedServer
                  = ConfigGetStringList(ConfigInfo, "DedicatedServer");
    StringListIterator  sli;

	const char	*Itr	=	NULL;

	char Domain[256];
	char Server[64];

	if( DedicatedServer == NULL )
    {
        return 0;
    }

	if( StringListIterator_Init(&sli, DedicatedServer) != 0 )
    {
        return -1;
    }

	Itr = sli.Next(&sli);
	while( Itr != NULL )
	{
		if( sscanf(Itr, "%s %s", Domain, Server) < 2 )
		{
			INFO("Invalid Option in `DedicatedServer' : %s\n", Itr);
			continue;
		}
		INFO("Add a dedicated Server %s for %s\n", Server, Domain);
		AddressChunk_AddADedicatedAddress_FromString(&Addresses, Domain, Server);
		Itr = sli.Next(&sli);
	}

	DedicatedServer->Free(DedicatedServer);

	return 0;
}

int InitAddress(ConfigFileInfo *ConfigInfo)
{
	StringList	*tcpaddrs	=	ConfigGetStringList(ConfigInfo, "TCPServer");
	StringList	*udpaddrs	=	ConfigGetStringList(ConfigInfo, "UDPServer");

	if( AddressChunk_Init(&Addresses) != 0 )
	{
		return -1;
	}

	if( tcpaddrs != NULL )
    {
        const char  *Itr = NULL;
        StringListIterator  sli;

        if( StringListIterator_Init(&sli, tcpaddrs) != 0 )
        {
            return -1;
        }

        Itr = sli.Next(&sli);
        while( Itr != NULL )
        {
            if( AddressChunk_AddATCPAddress_FromString(&Addresses, Itr) != 0 )
            {
                INFO("Bad address : %s\n", Itr);
            } else {
            }

            Itr = sli.Next(&sli);
        }
    }

	if( udpaddrs != NULL )
    {
        const char  *Itr = NULL;
        StringListIterator  sli;

        if( StringListIterator_Init(&sli, udpaddrs) != 0 )
        {
            return -1;
        }

        Itr = sli.Next(&sli);
        while( Itr != NULL )
        {
            if( AddressChunk_AddAUDPAddress_FromString(&Addresses, Itr) != 0 )
            {
                INFO("Bad address : %s\n", Itr);
            } else {
            }

            Itr = sli.Next(&sli);
        }
    }

	TCPAddresses_Array = AddressList_GetPtrList(AddressChunk_GetTCPPart(&Addresses), &TCPParallelFamilies);

	ParallelQuery = ConfigGetBoolean(ConfigInfo, "ParallelQuery");
	if( ParallelQuery == TRUE )
	{
		int NumberOfAddr;

		NumberOfAddr = udpaddrs == NULL ? 0 : udpaddrs->Count(udpaddrs);
		if( NumberOfAddr <= 0 )
		{
			ERRORMSG("No UDP server specified, cannot use parallel query.\n")
			ParallelQuery = FALSE;
		} else {
			AddressChunk_GetOneUDPBySubscript(&Addresses, &UDPParallelMainFamily, 0);

			UDPAddresses_Array = AddressList_GetPtrListOfFamily(AddressChunk_GetUDPPart(&Addresses), UDPParallelMainFamily);
		}
	}

	if( tcpaddrs != NULL ) {tcpaddrs->Free(tcpaddrs);}
	if( udpaddrs != NULL ) {udpaddrs->Free(udpaddrs);}

	return LoadDedicatedServer(ConfigInfo);
}

static sa_family_t GetAddress(ControlHeader		*Header,
							  DNSQuaryProtocol	ProtocolUsed,
							  struct sockaddr	**Addresses_List,
							  sa_family_t		*Family
							  )
{
	*Addresses_List = AddressChunk_GetDedicated(&Addresses, Family, Header -> RequestingDomain, &(Header -> RequestingDomainHashValue));
	if( *Addresses_List == NULL )
	{
		*Addresses_List = AddressChunk_GetOne(&Addresses, Family, ProtocolUsed);
	}
	return *Family;
}

BOOL SocketIsStillReadable(SOCKET Sock, int timeout)
{
	fd_set rfd;
	struct timeval TimeLimit = {timeout / 1000, (timeout % 1000) * 1000};

	FD_ZERO(&rfd);
	FD_SET(Sock, &rfd);

	switch(select(Sock + 1, &rfd, NULL, NULL, &TimeLimit))
	{
		case SOCKET_ERROR:
		case 0:
			return FALSE;
			break;
		case 1:
			return TRUE;
			break;
		default:
			return FALSE;
			break;
	}
}

void ClearSocketBuffer(SOCKET Sock)
{
	char BlackHole[128];

	int OriginErrorCode = GET_LAST_ERROR();

	while( SocketIsStillReadable(Sock, 0) )
	{
		recvfrom(Sock, BlackHole, sizeof(BlackHole), 0, NULL, NULL);
	}

	SET_LAST_ERROR(OriginErrorCode);
}

void ClearTCPSocketBuffer(SOCKET Sock, int Length)
{
	char BlackHole[128];

	int OriginErrorCode = GET_LAST_ERROR();

	while( Length > 0 )
	{
		Length -= recv(Sock,
						BlackHole,
						sizeof(BlackHole) < Length ? sizeof(BlackHole) : Length,
						MSG_NOSIGNAL
						);
	}

	SET_LAST_ERROR(OriginErrorCode);
}

static IPMisc	*IPMiscellaneous = NULL;

#define	IP_MISCELLANEOUS_BLOCK	(-1)
#define	IP_MISCELLANEOUS_NOTHING	(0)
static int DoIPMiscellaneous(char *RequestEntity,
                             int RequestLength,
                             const char *Domain,
                             BOOL BlockEnabled
                             )
{
    DnsSimpleParser p;

    if( DnsSimpleParser_Init(&p, RequestEntity, RequestLength, FALSE) != 0 )
    {
        return IP_MISCELLANEOUS_NOTHING;
    }

    if( p._Flags.Flags->ResponseCode != 0 )
    {
        return IP_MISCELLANEOUS_BLOCK;
    }

    if( IPMiscellaneous == NULL || BlockEnabled == FALSE )
    {
        return IP_MISCELLANEOUS_NOTHING;
    }

    switch( IPMiscellaneous->Process(IPMiscellaneous,
                                     RequestEntity,
                                     RequestLength)
          )
    {
    case IP_MISC_ACTION_BLOCK:
        DomainStatistic_Add(Domain, NULL, STATISTIC_TYPE_BLOCKEDMSG);
        ShowBlockedMessage(Domain, RequestEntity, RequestLength, "Bad package, discarded");
        return IP_MISCELLANEOUS_BLOCK;
        break;

    case IP_MISC_ACTION_NOTHING:
    default:
        return IP_MISCELLANEOUS_NOTHING;
        break;
    }
}

static int SendBack(SOCKET Socket,
					ControlHeader *Header,
					QueryContext *Context,
					int Length, /* Length of Response, including ControlHeader */
					char Protocal,
					StatisticType Type,
					BOOL BlockEnabled
					)
{
	int		Ret = 1;
	char	*RequestEntity = (char *)(Header + 1);
	int32_t	QueryContextNumber;
	QueryContextEntry	*ThisContext;

	if( DNSGetHostName(RequestEntity,
						Length - sizeof(ControlHeader),
						DNSJumpHeader(RequestEntity),
						Header -> RequestingDomain,
						sizeof(Header -> RequestingDomain)
						)
		< 0 )
	{
		return -1;
	}

	StrToLower(Header -> RequestingDomain);

	Header -> RequestingDomainHashValue = ELFHash(Header -> RequestingDomain, 0);

	QueryContextNumber = InternalInterface_QueryContextFind(Context, *(uint16_t *)RequestEntity, Header -> RequestingDomainHashValue);
	if( QueryContextNumber >= 0 )
	{
		int MiscellaneousRet;
		ThisContext = Bst_GetDataByNumber(Context, QueryContextNumber);

		DomainStatistic_Add(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue), Type);

		MiscellaneousRet = DoIPMiscellaneous(RequestEntity,
											 Length - sizeof(ControlHeader),
											 Header -> RequestingDomain,
											 BlockEnabled
											 );
		if( MiscellaneousRet != IP_MISCELLANEOUS_BLOCK )
		{   /* IP_MISCELLANEOUS_NOTHING */
			if( ThisContext -> NeededHeader == TRUE )
			{
				Ret = sendto(Socket,
							(const char *)Header,
							Length,
							0,
							(const struct sockaddr *)&(ThisContext -> Context.BackAddress.Addr),
							GetAddressLength(ThisContext -> Context.BackAddress.family)
							);

			} else {
				Ret = sendto(Socket,
							RequestEntity,
							Length - sizeof(ControlHeader),
							0,
							(const struct sockaddr *)&(ThisContext -> Context.BackAddress.Addr),
							GetAddressLength(ThisContext -> Context.BackAddress.family)
							);
			}

			InternalInterface_QueryContextRemoveByNumber(Context, QueryContextNumber);
			ShowNormalMessage(ThisContext -> Agent, Header -> RequestingDomain, RequestEntity, Length - sizeof(ControlHeader), Protocal);
			DNSCache_AddItemsToCache(RequestEntity, Length - sizeof(ControlHeader),time(NULL), Header -> RequestingDomain);
		}
	} else {
        /* Do not send back */
		/* ShowNormalMessage("Redundant Package", Header -> RequestingDomain, RequestEntity, Length - sizeof(ControlHeader), Protocal); */
	}

	return Ret;
}

static AddressList *TCPProxies = NULL;

int TCPProxies_Init(StringList *Proxies)
{
	const char *Itr = NULL;
	StringListIterator  sli;

	if( Proxies == NULL )
	{
		return 0;
	}

	if( TCPProxies == NULL )
	{
		TCPProxies = malloc(sizeof(AddressList));
		if( TCPProxies == NULL )
		{
			return -1;
		}

		if( AddressList_Init(TCPProxies) != 0 )
		{
			return -2;
		}
	}

	if( StringListIterator_Init(&sli, Proxies) != 0 )
    {
        return -3;
    }

	Itr = sli.Next(&sli);
	while( Itr != NULL )
	{
		if( AddressList_Add_From_String(TCPProxies, Itr, 1080) != 0 )
		{
			INFO("Bad address : %s\n", Itr);
		}

		Itr = sli.Next(&sli);
	}

	return 0;
}

static void TCPSwepOutput(QueryContextEntry *Entry, int Number)
{
	ShowTimeOutMessage(Entry -> Agent, Entry -> Type, Entry -> Domain, 'T');
	DomainStatistic_Add(Entry -> Domain, &(Entry -> HashValue), STATISTIC_TYPE_REFUSED);

	if( Number == 1 )
	{
		AddressChunk_Advance(&Addresses, DNS_QUARY_PROTOCOL_TCP);
		if( TCPProxies != NULL )
		{
			AddressList_Advance(TCPProxies);
		}
	}
}

static BOOL SocketIsWritable(SOCKET sock, int Timeout)
{
	struct timeval TimeLimit = {Timeout / 1000, (Timeout % 1000) * 1000};
	fd_set rfd;

	if( sock == INVALID_SOCKET )
	{
		return FALSE;
	}

	FD_ZERO(&rfd);
	FD_SET(sock, &rfd);

	switch(select(sock + 1, NULL, &rfd, NULL, &TimeLimit))
	{
		case 0:
		case SOCKET_ERROR:
			return FALSE;
			break;

		default:
			return TRUE;
			break;
	}
}

static SOCKET ConnectToTCPServer(struct sockaddr    **ServerAddressesList,
                                sa_family_t         *FamiliesList,
                                const char          *Type
                                )
{
#   define  CONNECT_TIMEOUT 5

#   define  NUMBER_OF_SOCKETS 5
	SOCKET	TCPSockets[NUMBER_OF_SOCKETS];
	int		Itr;
	BOOL	State = FALSE;
	int		MaxFd = -1;

#ifdef WIN32
	clock_t TimeStart;
#endif

	fd_set rfd;
	struct timeval TimeLimit = {CONNECT_TIMEOUT, 0};

	INFO("Connecting to %s ...\n", Type);

#ifdef WIN32
	TimeStart = clock();
#endif

    for( Itr = 0; Itr != NUMBER_OF_SOCKETS; ++Itr)
    {
		TCPSockets[Itr] = INVALID_SOCKET;
    }

    FD_ZERO(&rfd);

	for( Itr = 0; Itr != NUMBER_OF_SOCKETS; ++Itr)
	{
		if( ServerAddressesList[Itr] == NULL )
		{
			break;
		}

        TCPSockets[Itr] = socket(FamiliesList[Itr], SOCK_STREAM, IPPROTO_TCP);
        if( TCPSockets[Itr] == INVALID_SOCKET )
        {
			continue;
        }

        SetSocketNonBlock(TCPSockets[Itr], TRUE);

		if( connect(TCPSockets[Itr], ServerAddressesList[Itr], GetAddressLength(FamiliesList[Itr])) != 0 )
		{
			if( GET_LAST_ERROR() != CONNECT_FUNCTION_BLOCKED )
			{
				CLOSE_SOCKET(TCPSockets[Itr]);
				continue;
			}
		}

		if( TCPSockets[Itr] > MaxFd )
		{
			MaxFd = TCPSockets[Itr];
		}

		FD_SET(TCPSockets[Itr], &rfd);

		State |= TRUE;
    }

    if( State == FALSE )
    {
		ERRORMSG("Cannot connect to %s.\n", Type);
		return INVALID_SOCKET;
    }
/*
	TCPSocket = socket(Family, SOCK_STREAM, IPPROTO_TCP);
	if( TCPSocket == INVALID_SOCKET )
	{
		ERRORMSG("Cannot create socket for TCP query.\n");
		return INVALID_SOCKET;
	}

	SetSocketNonBlock(TCPSocket, TRUE);

	if( connect(TCPSocket, ServerAddress, GetAddressLength(Family)) != 0 )
	{
		if( GET_LAST_ERROR() != CONNECT_FUNCTION_BLOCKED )
		{
			ERRORMSG("Cannot connect to %s.\n", Type);
			CLOSE_SOCKET(TCPSocket);
			return INVALID_SOCKET;
		}
	}

	FD_ZERO(&rfd);
	FD_SET(TCPSocket, &rfd);
*/
	switch(select(MaxFd + 1, NULL, &rfd, NULL, &TimeLimit))
	{
		case 0:
		case SOCKET_ERROR:
		{
			for( Itr = 0; Itr != NUMBER_OF_SOCKETS; ++Itr )
			{
				CloseTCPConnection(TCPSockets[Itr]);
			}

			INFO("Connecting to %s timed out.\n", Type);
			return INVALID_SOCKET;
		}
			break;

		default:
		{
			SOCKET	Ret = INVALID_SOCKET;
			int		Number = -1;
			for( Itr = 0; Itr != NUMBER_OF_SOCKETS; ++Itr )
			{
				if( TCPSockets[Itr] != INVALID_SOCKET && FD_ISSET(TCPSockets[Itr], &rfd) )
				{
					Ret = TCPSockets[Itr];
					Number = Itr;
				} else {
					CloseTCPConnection(TCPSockets[Itr]);
				}
			}
#ifdef WIN32
			INFO("TCP connection to %s established (No %d). Time consumed : %dms\n", Type, Number, (int)((clock() - TimeStart) * 1000 / CLOCKS_PER_SEC));
#else
			INFO("TCP connection to %s established (No %d). Time consumed : %d.%ds\n", Type, Number, CONNECT_TIMEOUT == TimeLimit.tv_sec ? 0 : ((int)(CONNECT_TIMEOUT - 1 - TimeLimit.tv_sec)), CONNECT_TIMEOUT == TimeLimit.tv_sec ? 0 : ((int)(1000000 - TimeLimit.tv_usec)));
#endif
			return Ret;
		}
			break;
	}

	return INVALID_SOCKET;
}

static int TCPSend_Wrapper(SOCKET Sock, const char *Start, int Length)
{
#define DEFAULT_TIME_OUT__SEND 2000 /*  */
	while( send(Sock, Start, Length, MSG_NOSIGNAL) != Length )
	{
		int LastError = GET_LAST_ERROR();
#ifdef WIN32
		if( LastError == WSAEWOULDBLOCK || LastError == WSAEINPROGRESS )
		{
			if( SocketIsWritable(Sock, 2000) == TRUE )
			{
				continue;
			}
		}
#else
		if( LastError == EAGAIN || LastError == EWOULDBLOCK )
		{
			if( SocketIsWritable(Sock, 2000) == TRUE )
			{
				continue;
			}
		}
#endif
		return (-1) * LastError;
	}

	return Length;
}

static int TCPRecv_Wrapper(SOCKET Sock, char *Buffer, int BufferSize)
{
	int Recvlength;

	while( (Recvlength = recv(Sock, Buffer, BufferSize, MSG_NOSIGNAL)) < 0 )
	{
		int LastError = GET_LAST_ERROR();
#ifdef WIN32
		if( LastError == WSAEWOULDBLOCK || LastError == WSAEINPROGRESS )
		{
			if( SocketIsStillReadable(Sock, 20000) == TRUE )
			{
				continue;
			}
		}
#else
		if( LastError == EAGAIN || LastError ==  EWOULDBLOCK )
		{
			if( SocketIsStillReadable(Sock, 20000) == TRUE )
			{
				continue;
			}
		}
#endif
		return (-1) * LastError;
	}

	return Recvlength;
}

static void ShowSocketError(const char *Prompts, int ErrorNum)
{
	char	ErrorMessage[320];

	if( ErrorMessages == TRUE )
	{
		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));
		ERRORMSG("%s : %d : %s\n", Prompts, ErrorNum, ErrorMessage);
	}
}

static int TCPProxyPreparation(SOCKET Sock, const struct sockaddr	*NestedAddress, sa_family_t Family)
{
    char AddressString[LENGTH_OF_IPV6_ADDRESS_ASCII];
    char NumberOfCharacter;
    unsigned short Port;
    char RecvBuffer[16];
    int ret;

    if( Family == AF_INET )
    {
		strcpy(AddressString, inet_ntoa(((const struct sockaddr_in *)NestedAddress) -> sin_addr));
		Port = ((const struct sockaddr_in *)NestedAddress) -> sin_port;
    } else {
		IPv6AddressToAsc(&(((const struct sockaddr_in6 *)NestedAddress) -> sin6_addr), AddressString);
		Port = ((const struct sockaddr_in6 *)NestedAddress) -> sin6_port;
    }

	if( TCPSend_Wrapper(Sock, "\x05\x01\x00", 3) != 3 )
	{
		ShowSocketError("Cannot communicate with TCP proxy, negotiation error", GET_LAST_ERROR());
		return -1;
	}

    if( (ret = TCPRecv_Wrapper(Sock, RecvBuffer, 2)) != 2 )
    {
		/*printf("--------------GetLastError : %d, ret : %d\n", GET_LAST_ERROR(), ret);*/
		ShowSocketError("Cannot communicate with TCP proxy, negotiation error", GET_LAST_ERROR());
        return -2;
    }

	if( RecvBuffer[0] != '\x05' || RecvBuffer[1] != '\x00' )
	{
		/*printf("---------3 : %x %x\n", RecvBuffer[0], RecvBuffer[1]);*/
		ShowSocketError("Cannot communicate with TCP proxy, negotiation error", GET_LAST_ERROR());
		return -3;
	}

	INFO("Connecting to TCP server.\n");

	if( TCPSend_Wrapper(Sock, "\x05\x01\x00\x03", 4) != 4 )
	{
		ShowSocketError("Cannot communicate with TCP proxy, connection to TCP server error", GET_LAST_ERROR());
		return -4;
	}
	NumberOfCharacter = strlen(AddressString);
	if( TCPSend_Wrapper(Sock, &NumberOfCharacter, 1) != 1 )
	{
		ShowSocketError("Cannot communicate with TCP proxy, connection to TCP server error", GET_LAST_ERROR());
		return -5;
	}
	if( TCPSend_Wrapper(Sock, AddressString, NumberOfCharacter) != NumberOfCharacter )
	{
		ShowSocketError("Cannot communicate with TCP proxy, connection to TCP server error", GET_LAST_ERROR());
		return -6;
	}
	if( TCPSend_Wrapper(Sock, (const char *)&Port, sizeof(Port)) != sizeof(Port) )
	{
		ShowSocketError("Cannot communicate with TCP proxy, connection to TCP server error", GET_LAST_ERROR());
		return -7;
	}

	TCPRecv_Wrapper(Sock, RecvBuffer, 4);
	if( RecvBuffer[1] != '\x00' )
	{
		ShowSocketError("Cannot communicate with TCP proxy, connection to TCP server error", GET_LAST_ERROR());
		return -8;
	}

	switch( RecvBuffer[3] )
	{
		case 0x01:
			NumberOfCharacter = 6;
			break;

		case 0x03:
			TCPRecv_Wrapper(Sock, &NumberOfCharacter, 1);
			NumberOfCharacter += 2;
			break;

		case 0x04:
			NumberOfCharacter = 18;
			break;

		default:
			/*printf("------Here : %d %d %d %d\n", RecvBuffer[0], RecvBuffer[1], RecvBuffer[2], RecvBuffer[3]);*/
			ShowSocketError("Cannot communicate with TCP proxy, connection to TCP server error", GET_LAST_ERROR());
			return -9;
	}
	ClearTCPSocketBuffer(Sock, NumberOfCharacter);

	INFO("Connected to TCP server.\n");

	return 0;

}

int QueryDNSViaTCP(void)
{
	static QueryContext	Context;

	SOCKET	TCPQueryIncomeSocket;
	SOCKET	TCPQueryOutcomeSocket;
	time_t	TCPQueryOutcomeSocketLast;
	SOCKET	*TCPQueryActiveSocketPtr;
	time_t	*TCPQueryActiveSocketLastPtr;
	#define TIME_EXPIRED_SECOND	2

	SOCKET	SendBackSocket;

	SocketPool	DedicatedSockets;

	int		NumberOfQueryBeforeSwep = 0;

	static fd_set	ReadSet, ReadySet;

	static const struct timeval	LongTime = {3600, 0};
	static const struct timeval	ShortTime = {10, 0};

	struct timeval	TimeLimit = LongTime;

	int		MaxFd;

	static char		RequestEntity[2048];
	ControlHeader	*Header = (ControlHeader *)RequestEntity;

	TCPQueryIncomeSocket = InternalInterface_TryOpenLocal(10100, INTERNAL_INTERFACE_TCP_QUERY);
	TCPQueryOutcomeSocket = INVALID_SOCKET;
	TCPQueryActiveSocketPtr = NULL;

	SendBackSocket = InternalInterface_GetSocket(INTERNAL_INTERFACE_UDP_INCOME);

	if( SocketPool_Init(&DedicatedSockets) != 0 )
	{
		ERRORMSG("Init ds failed (806).\n");
		return -1;
	}

	MaxFd = TCPQueryIncomeSocket;
	FD_ZERO(&ReadSet);
	FD_ZERO(&ReadySet);
	FD_SET(TCPQueryIncomeSocket, &ReadSet);

	InternalInterface_InitQueryContext(&Context);

	while( TRUE )
	{
		ReadySet = ReadSet;

		switch( select(MaxFd + 1, &ReadySet, NULL, NULL, &TimeLimit) )
		{
			case SOCKET_ERROR:
				{
					int LastError = GET_LAST_ERROR();
					ERRORMSG("SOCKET_ERROR Reached, 1062.\n");
					if( FatalErrorDecideding(LastError) != 0 )
					{
						ERRORMSG("\n\n\n\n\n\n\n\n\n\n");
						ERRORMSG(" !!!!! Something bad happend, this program will try to recovery after 10 seconds (1066). %d\n", LastError);
						SLEEP(10000);

						if( TCPQueryOutcomeSocket != INVALID_SOCKET )
						{
							CLOSE_SOCKET(TCPQueryOutcomeSocket);
							TCPQueryOutcomeSocket = INVALID_SOCKET;
						}
						TCPQueryActiveSocketPtr = NULL;
						SocketPool_CloseAll(&DedicatedSockets);
						MaxFd = TCPQueryIncomeSocket;
						FD_ZERO(&ReadSet);
						FD_ZERO(&ReadySet);
						FD_SET(TCPQueryIncomeSocket, &ReadSet);
					}
				}
				break;

			case 0:
				if( InternalInterface_QueryContextSwep(&Context, 10, TCPSwepOutput) == TRUE )
				{
					TimeLimit = LongTime;
				} else {
					TimeLimit = ShortTime;
				}

				NumberOfQueryBeforeSwep = 0;
				break;

			default:
				TimeLimit = ShortTime;

				++NumberOfQueryBeforeSwep;
				if( NumberOfQueryBeforeSwep > 1024 )
				{
					InternalInterface_QueryContextSwep(&Context, 2, TCPSwepOutput);
					NumberOfQueryBeforeSwep = 0;
				}

				if( FD_ISSET(TCPQueryIncomeSocket, &ReadySet) )
				{
					int				RecvState, SendState;
					SOCKET			*SendOutSocket;
					sa_family_t		NewFamily;
					struct sockaddr	*NewAddress[2] = {NULL, NULL};
					static char		TCPRerequest[2048 - sizeof(ControlHeader) + 2];
					uint16_t		*TCPLength = (uint16_t *)TCPRerequest;
					int				TCPRerequestLength;

					RecvState = recvfrom(TCPQueryIncomeSocket,
								RequestEntity,
								sizeof(RequestEntity),
								0,
								NULL,
								NULL
								);

					if( RecvState < 1 )
					{
						ERRORMSG("RecvState : %d (833).\n", RecvState);
						break;
					} else {

					}

					/* Preparing socket */
					if( TCPProxies == NULL )
					{
						/* Diretc connection */
						NewAddress[0] = AddressChunk_GetDedicated(  &Addresses,
																	&NewFamily,
																	Header -> RequestingDomain,
																	&(Header -> RequestingDomainHashValue)
																	);
						if( NewAddress[0] != NULL ) /* Dedicated server */
						{
							SendOutSocket = SocketPool_Fetch(&DedicatedSockets, NewAddress[0], &TCPQueryActiveSocketLastPtr);
							if( SendOutSocket == NULL )
							{
								/* Something wrong */
								break;
							}

							if( (time(NULL) - *TCPQueryActiveSocketLastPtr) > TIME_EXPIRED_SECOND || SocketIsWritable(*SendOutSocket, 0) == FALSE )
							{
								if( *SendOutSocket != INVALID_SOCKET )
								{
									FD_CLR(*SendOutSocket, &ReadSet);
									CLOSE_SOCKET(*SendOutSocket);
								}

								*SendOutSocket = ConnectToTCPServer(NewAddress, &NewFamily, "TCP server");
								if( *SendOutSocket == INVALID_SOCKET )
								{
									break;
								}

								TCPQueryActiveSocketPtr = SendOutSocket;
								*TCPQueryActiveSocketLastPtr = time(NULL);
							}
						} else { /* General server */
							if( (time(NULL) - TCPQueryOutcomeSocketLast) > TIME_EXPIRED_SECOND || SocketIsWritable(TCPQueryOutcomeSocket, 0) == FALSE )
							{
								if( TCPQueryOutcomeSocket != INVALID_SOCKET )
								{
									FD_CLR(TCPQueryOutcomeSocket, &ReadSet);
									CLOSE_SOCKET(TCPQueryOutcomeSocket);
								}
								TCPQueryOutcomeSocket = ConnectToTCPServer(TCPAddresses_Array, TCPParallelFamilies, "TCP server");
								if( TCPQueryOutcomeSocket == INVALID_SOCKET )
								{
									break;
								}
								TCPQueryOutcomeSocketLast = time(NULL);
							}
							TCPQueryActiveSocketPtr = &TCPQueryOutcomeSocket;
							TCPQueryActiveSocketLastPtr = &TCPQueryOutcomeSocketLast;

						}
/*
						if( *TCPQueryActiveSocketPtr == INVALID_SOCKET )
						{
							break;
						}
*/
						if( *TCPQueryActiveSocketPtr > MaxFd )
						{
							MaxFd = *TCPQueryActiveSocketPtr;
						}

						FD_SET(*TCPQueryActiveSocketPtr, &ReadSet);
					} else {
						/* Connecting via proxy */
						if( (time(NULL) - TCPQueryOutcomeSocketLast) > TIME_EXPIRED_SECOND || SocketIsWritable(TCPQueryOutcomeSocket, 0) == FALSE )
						{
							struct sockaddr	*NewProxy[2] = {NULL, NULL};
							sa_family_t	ProxyFamily;
							int ret;

							if( TCPQueryOutcomeSocket != INVALID_SOCKET )
							{
								FD_CLR(TCPQueryOutcomeSocket, &ReadSet);
								CLOSE_SOCKET(TCPQueryOutcomeSocket);
							}

							GetAddress( (ControlHeader *)RequestEntity,
										DNS_QUARY_PROTOCOL_TCP,
										&(NewAddress[0]),
										&NewFamily
										);
							NewProxy[0] = AddressList_GetOne(TCPProxies, &ProxyFamily);
							TCPQueryOutcomeSocket = ConnectToTCPServer(NewProxy, &ProxyFamily, "TCP proxy");
							if( TCPQueryOutcomeSocket == INVALID_SOCKET )
							{
								AddressList_Advance(TCPProxies);
								break;
							}

							ret = TCPProxyPreparation(TCPQueryOutcomeSocket, NewAddress[0], NewFamily);
							if( ret != 0 )
							{
								CloseTCPConnection(TCPQueryOutcomeSocket);
								TCPQueryOutcomeSocket = INVALID_SOCKET;
								AddressList_Advance(TCPProxies);
								break;
							}

							if( TCPQueryOutcomeSocket > MaxFd )
							{
								MaxFd = TCPQueryOutcomeSocket;
							}

							FD_SET(TCPQueryOutcomeSocket, &ReadSet);
							TCPQueryOutcomeSocketLast = time(NULL);
						}

						TCPQueryActiveSocketPtr = &TCPQueryOutcomeSocket;
						TCPQueryActiveSocketLastPtr = &TCPQueryOutcomeSocketLast;
					}
					/* Socket preparing done */

					InternalInterface_QueryContextAddUDP(&Context, Header);
/*
					if( TCPProxies != NULL )
					{
						send(TCPQueryActiveSocketPtr, 0x47, 1, MSG_NOSIGNAL);
					}
*/
					TCPRerequestLength = RecvState - sizeof(ControlHeader) + 2;
					if( TCPRerequestLength > sizeof(TCPRerequest) )
					{
						ERRORMSG("Segment too large (902).\n");
						break;
					}
					*TCPLength = htons(TCPRerequestLength - 2);
					memcpy(TCPRerequest + 2, RequestEntity + sizeof(ControlHeader), TCPRerequestLength - 2);

					SendState = TCPSend_Wrapper(*TCPQueryActiveSocketPtr, TCPRerequest, TCPRerequestLength);
					if( SendState < 0 )
					{
						ShowSocketError("Sending to TCP server failed (912)", (-1) * SendState);
						FD_CLR(*TCPQueryActiveSocketPtr, &ReadSet);
						CloseTCPConnection(*TCPQueryActiveSocketPtr);
						*TCPQueryActiveSocketPtr = INVALID_SOCKET;
						AddressList_Advance(TCPProxies);
						break;
					} else {

					}

				} else {
					int			State;
					uint16_t	TCPLength;
					SOCKET		*ActiveSocket;

					if( FD_ISSET(*TCPQueryActiveSocketPtr, &ReadySet) )
					{
						ActiveSocket = TCPQueryActiveSocketPtr;
					} else if( FD_ISSET(TCPQueryOutcomeSocket, &ReadySet) ){
						ActiveSocket = &TCPQueryOutcomeSocket;
						TCPQueryActiveSocketLastPtr = &TCPQueryOutcomeSocketLast;
					} else {
						ActiveSocket = SocketPool_IsSet(&DedicatedSockets, &ReadySet, &TCPQueryActiveSocketLastPtr);
						if( ActiveSocket == NULL )
						{
							ERRORMSG("Something wrong (1025).\n");
							break;
						}
					}
/*
					if( TCPProxies != NULL )
					{
						char _0x72;
						recv(TCPQueryActiveSocketPtr, _0x72, 1, MSG_NOSIGNAL);
					}
*/
					if( recv(*ActiveSocket, (char *)&TCPLength, 2, MSG_NOSIGNAL) < 2 )
					{
						FD_CLR(*ActiveSocket, &ReadSet);
                        CloseTCPConnection(*ActiveSocket);
						*ActiveSocket = INVALID_SOCKET;
                        INFO("TCP %s closed the connection.\n", TCPProxies == NULL ? "server" : "proxy");
						break;
					}

					TCPLength = ntohs(TCPLength);

					if( TCPLength > sizeof(RequestEntity) - sizeof(ControlHeader) )
					{
						FD_CLR(*ActiveSocket, &ReadSet);
						CloseTCPConnection(*ActiveSocket);
						AddressChunk_Advance(&Addresses, DNS_QUARY_PROTOCOL_TCP);
						*ActiveSocket = INVALID_SOCKET;
						INFO("TCP stream is longer than the buffer, discarded.\n");
						break;
					}

					State = recv(*ActiveSocket,
								RequestEntity + sizeof(ControlHeader),
								TCPLength,
								MSG_NOSIGNAL
								);

					if( State != TCPLength )
					{
						FD_CLR(*ActiveSocket, &ReadSet);
						CloseTCPConnection(*ActiveSocket);
						AddressChunk_Advance(&Addresses, DNS_QUARY_PROTOCOL_TCP);
						*ActiveSocket = INVALID_SOCKET;
						INFO("TCP stream is too short, server may have some failures.\n");
						break;
					}
					*TCPQueryActiveSocketLastPtr = time(NULL);

					if( SendBack(SendBackSocket,
                                 Header,
                                 &Context,
                                 State + sizeof(ControlHeader),
                                 'T',
                                 STATISTIC_TYPE_TCP,
                                 FALSE
                                 ) <= 0 )
					{
						ERRORMSG("TCP sending back error (1085).\n");
					}
				}
		}
	}
}

int InitBlockedIP(StringList *l)
{
	const char	*Itr = NULL;
	StringListIterator  sli;

	if( l == NULL )
	{
		return 0;
	}

    if( StringListIterator_Init(&sli, l) != 0 )
    {
        return -1;
    }

	if( IPMiscellaneous == NULL )
	{
		IPMiscellaneous = SafeMalloc(sizeof(IPMisc));
		if( IPMisc_Init(IPMiscellaneous) != 0 )
        {
            return -2;
        }
	}

	Itr = sli.Next(&sli);
	while( Itr != NULL )
	{
        IPMiscellaneous->AddBlockFromString(IPMiscellaneous, Itr);

		Itr = sli.Next(&sli);
	}

	l->Free(l);

	return 0;
}

int InitIPSubstituting(StringList *l)
{
	const char	*Itr = NULL;
	StringListIterator  sli;

	char	Origin_Str[LENGTH_OF_IPV6_ADDRESS_ASCII];
	char	Substituted_Str[LENGTH_OF_IPV6_ADDRESS_ASCII];

	if( l == NULL )
	{
		return 0;
	}

	if( StringListIterator_Init(&sli, l) != 0 )
    {
        return -1;
    }

	if( IPMiscellaneous == NULL )
	{
		IPMiscellaneous = SafeMalloc(sizeof(IPMisc));
		if( IPMisc_Init(IPMiscellaneous) != 0 )
        {
            return -2;
        }
	}

	Itr = sli.Next(&sli);
	while( Itr != NULL )
	{
		sscanf(Itr, "%s %s", Origin_Str, Substituted_Str);

		IPMiscellaneous->AddSubstituteFromString(IPMiscellaneous,
                                                 Origin_Str,
                                                 Substituted_Str
                                                 );

		Itr = sli.Next(&sli);
	}

	l->Free(l);

	return 0;
}

static int SendQueryViaUDP(SOCKET			Socket,
							const char		*RequestEntity,
							int				EntityLength,
							struct sockaddr	**Addresses_List,
							sa_family_t		Family
							)
{
	int		AddrLen = GetAddressLength(Family);

	int		StateOfSending = 0;

	while( *Addresses_List != NULL )
	{
		StateOfSending |= (sendto(Socket, RequestEntity, EntityLength, 0, *Addresses_List, AddrLen) > 0);

		++Addresses_List;
	}

	return StateOfSending;
}

static void UDPSwepOutput(QueryContextEntry *Entry, int Number)
{
	ShowTimeOutMessage(Entry -> Agent, Entry -> Type, Entry -> Domain, 'U');
	DomainStatistic_Add(Entry -> Domain, &(Entry -> HashValue), STATISTIC_TYPE_REFUSED);

	if( Number == 1 && ParallelQuery == FALSE )
	{
		AddressChunk_Advance(&Addresses, DNS_QUARY_PROTOCOL_UDP);
	}
}

int QueryDNSViaUDP(void)
{
	static QueryContext	Context;

	SOCKET	UDPQueryIncomeSocket;
	SOCKET	UDPQueryOutcomeSocket;
	SOCKET	SendBackSocket;

	int		NumberOfQueryBeforeSwep = 0;

	static fd_set	ReadSet, ReadySet;

	static const struct timeval	LongTime = {3600, 0};
	static const struct timeval	ShortTime = {5, 0};

	struct timeval	TimeLimit = LongTime;

	int		MaxFd;

    /* Infos of last used server. */
	sa_family_t		LastFamily = AF_INET;

	static char		RequestEntity[2048];
	ControlHeader	*Header = (ControlHeader *)RequestEntity;

	UDPQueryIncomeSocket =	InternalInterface_TryOpenLocal(10125, INTERNAL_INTERFACE_UDP_QUERY);
	UDPQueryOutcomeSocket = InternalInterface_OpenASocket(LastFamily, NULL);

	SendBackSocket = InternalInterface_GetSocket(INTERNAL_INTERFACE_UDP_INCOME);

	if( UDPQueryOutcomeSocket == INVALID_SOCKET )
	{
		return -1;
	}

	MaxFd = UDPQueryIncomeSocket > UDPQueryOutcomeSocket ? UDPQueryIncomeSocket : UDPQueryOutcomeSocket;
	FD_ZERO(&ReadSet);
	FD_ZERO(&ReadySet);
	FD_SET(UDPQueryIncomeSocket, &ReadSet);
	FD_SET(UDPQueryOutcomeSocket, &ReadSet);

	InternalInterface_InitQueryContext(&Context);

	while( TRUE )
	{
		ReadySet = ReadSet;

		switch( select(MaxFd + 1, &ReadySet, NULL, NULL, &TimeLimit) )
		{
			case SOCKET_ERROR:
				{
					int LastError = GET_LAST_ERROR();
					ERRORMSG("SOCKET_ERROR Reached, 1510.\n");
					if( FatalErrorDecideding(LastError) != 0 )
					{
						ERRORMSG("\n\n\n\n\n\n\n\n\n\n");
						ERRORMSG(" !!!!! Something bad happend, this program will try to recovery after 10 seconds (1514). %d\n", LastError);
						SLEEP(10000);

						MaxFd = UDPQueryIncomeSocket > UDPQueryOutcomeSocket ? UDPQueryIncomeSocket : UDPQueryOutcomeSocket;
						FD_ZERO(&ReadSet);
						FD_ZERO(&ReadySet);
						FD_SET(UDPQueryIncomeSocket, &ReadSet);
						FD_SET(UDPQueryOutcomeSocket, &ReadSet);
					}
				}
				break;

			case 0:
				if( InternalInterface_QueryContextSwep(&Context, 2, UDPSwepOutput) == TRUE )
				{
					TimeLimit = LongTime;
				} else {
					TimeLimit = ShortTime;
				}

				NumberOfQueryBeforeSwep = 0;
				break;

			default:
				TimeLimit = ShortTime;

				++NumberOfQueryBeforeSwep;
				if( NumberOfQueryBeforeSwep > 1024 )
				{
					InternalInterface_QueryContextSwep(&Context, 5, UDPSwepOutput);
					NumberOfQueryBeforeSwep = 0;
				}

				if( FD_ISSET(UDPQueryIncomeSocket, &ReadySet) )
				{
					int State;
					struct sockaddr	*NewAddress[2];
					sa_family_t	NewFamily;

					State = recvfrom(UDPQueryIncomeSocket,
									RequestEntity,
									sizeof(RequestEntity),
									0,
									NULL,
									NULL
									);

					if( State < 1 )
					{
						break;
					}

					InternalInterface_QueryContextAddUDP(&Context, Header);

					NewAddress[0] = AddressChunk_GetDedicated(&Addresses, &NewFamily, Header -> RequestingDomain, &(Header -> RequestingDomainHashValue));
					/* If ParallelQuery is off or a dedicated server is specified, */
					if( ParallelQuery == FALSE || NewAddress[0] != NULL )
					{   /* then use only one server */
						if( NewAddress[0] == NULL )
						{
							NewAddress[0] = AddressChunk_GetOne(&Addresses, &NewFamily, DNS_QUARY_PROTOCOL_UDP);
						}

						NewAddress[1] = NULL;

						if( NewFamily != LastFamily )
						{
							if( UDPQueryOutcomeSocket != INVALID_SOCKET )
							{
								FD_CLR(UDPQueryOutcomeSocket, &ReadSet);
								CLOSE_SOCKET(UDPQueryOutcomeSocket);
							}

							UDPQueryOutcomeSocket = InternalInterface_OpenASocket(NewFamily, NULL);
							if( UDPQueryOutcomeSocket == INVALID_SOCKET )
							{
								LastFamily = AF_UNSPEC;
								break;
							}

							LastFamily = NewFamily;
							if( UDPQueryOutcomeSocket > MaxFd )
							{
								MaxFd = UDPQueryOutcomeSocket;
							}
							FD_SET(UDPQueryOutcomeSocket, &ReadSet);
						}

						SendQueryViaUDP(UDPQueryOutcomeSocket,
										RequestEntity + sizeof(ControlHeader),
										State - sizeof(ControlHeader),
										NewAddress,
										NewFamily
										);
					} else {
                        /* otherwise use those all servers. */
                        if( LastFamily != UDPParallelMainFamily )
						{
							if( UDPQueryOutcomeSocket != INVALID_SOCKET )
							{
								FD_CLR(UDPQueryOutcomeSocket, &ReadSet);
								CLOSE_SOCKET(UDPQueryOutcomeSocket);
							}

							UDPQueryOutcomeSocket = InternalInterface_OpenASocket(UDPParallelMainFamily, NULL);
							if( UDPQueryOutcomeSocket == INVALID_SOCKET )
							{
								LastFamily = AF_UNSPEC;
								break;
							}

							LastFamily = UDPParallelMainFamily;
							if( UDPQueryOutcomeSocket > MaxFd )
							{
								MaxFd = UDPQueryOutcomeSocket;
							}
							FD_SET(UDPQueryOutcomeSocket, &ReadSet);
						}

						SendQueryViaUDP(UDPQueryOutcomeSocket,
										RequestEntity + sizeof(ControlHeader),
										State - sizeof(ControlHeader),
										UDPAddresses_Array,
										UDPParallelMainFamily
										);
					}
				} else {
					int State;

					State = recvfrom(UDPQueryOutcomeSocket,
									RequestEntity + sizeof(ControlHeader),
									sizeof(RequestEntity) - sizeof(ControlHeader),
									0,
									NULL,
									NULL
									);

					if( State < 1 )
					{
						break;
					}

					SendBack(SendBackSocket,
                             Header,
                             &Context,
                             State + sizeof(ControlHeader),
                             'U',
                             STATISTIC_TYPE_UDP,
                             TRUE
                             );
				}
			break;
		}
	}
}

int SetSocketSendTimeLimit(SOCKET sock, int time)
{
#ifdef WIN32
	return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&time, sizeof(time));
#else
	struct timeval Time = {time / 1000, (time % 1000) * 1000};
	return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Time, sizeof(Time));
#endif
}

int SetSocketRecvTimeLimit(SOCKET sock, int time)
{
#ifdef WIN32
	return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&time, sizeof(time));
#else
	struct timeval Time = {time / 1000, (time % 1000) * 1000};
	return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Time, sizeof(Time));
#endif
}

int SetSocketNonBlock(SOCKET sock, BOOL NonBlocked)
{
#ifdef WIN32
	unsigned long NonBlock = 1;

	if( ioctlsocket(sock, FIONBIO, &NonBlock) != 0 )
	{
		return -1;
	} else {
		return 0;
	}
#else
	int Flags;
	int BlockFlag;

	Flags = fcntl(sock, F_GETFL, 0);
	if( Flags < 0 )
	{
		return -1;
	}

	if( NonBlocked == TRUE )
	{
        BlockFlag = O_NONBLOCK;
	} else {
        BlockFlag = ~O_NONBLOCK;
	}

	if( fcntl(sock, F_SETFL, Flags | BlockFlag) < 0 )
	{
		return -1;
	}

	return 0;
#endif
}

BOOL TCPSocketIsHealthy(SOCKET sock)
{
	if(sock != INVALID_SOCKET){
		/* Testing effectiveness of `sock' */
		fd_set rfd;
		struct timeval TimeLimit = {0, 0};

		FD_ZERO(&rfd);
		FD_SET(sock, &rfd);

		switch(select(sock + 1, &rfd, NULL, NULL, &TimeLimit)){
			case 0:
				/* Effective */
				return TRUE;
				break;
			case 1:{
				char Buffer[1];
				int state = recv(sock, Buffer, 1, MSG_PEEK);

				if(state == 0 || state == SOCKET_ERROR)
					break;
				else
					/* Effective */
					return TRUE;
				   }
				break;
			case SOCKET_ERROR:
				break;
			default:
				break;
		}
		/* Ineffective */
	}
	/* Ineffective */
	return FALSE;
}

void CloseTCPConnection(SOCKET sock)
{
	if(sock != INVALID_SOCKET){
		CLOSE_SOCKET(sock);
	}
}

void TransferStart(BOOL StartTCP)
{
	ThreadHandle t;
	CREATE_THREAD(QueryDNSViaUDP, NULL, t);
	DETACH_THREAD(t);

	if( StartTCP == TRUE )
	{
		CREATE_THREAD(QueryDNSViaTCP, NULL, t);
		DETACH_THREAD(t);
	}
}











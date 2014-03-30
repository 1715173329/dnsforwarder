#include "request_response.h"
#include "extendablebuffer.h"
#include "domainstatistic.h"
#include "dnsparser.h"
#include "dnsgenerator.h"
#include "dnscache.h"
#include "addresschunk.h"
#include "ipchunk.h"
#include "internalsocket.h"
#include "utils.h"
#include "common.h"

static AddressChunk	Addresses;
static BOOL			ParallelQuery;

static sa_family_t	ParallelMainFamily;
static Array		Addresses_Array;

static int LoadDedicatedServer(void)
{
	const StringList	*DedicatedServer	=	ConfigGetStringList(&ConfigInfo, "DedicatedServer");

	const char	*Itr	=	NULL;

	char Domain[256];
	char Server[64];

	Itr = StringList_GetNext(DedicatedServer, NULL);
	while( Itr != NULL )
	{
		if( sscanf(Itr, "%s %s", Domain, Server) < 2 )
		{
			INFO("Invalid Option in `DedicatedServer' : %s\n", Itr);
			continue;
		}
		INFO("Add a dedicated Server %s for %s\n", Server, Domain);
		AddressChunk_AddADedicatedAddress_FromString(&Addresses, Domain, Server);
		Itr = StringList_GetNext(DedicatedServer, Itr);
	}

	StringList_Free(DedicatedServer);

	return 0;
}

int InitAddress(void)
{
	StringList	*tcpaddrs	=	ConfigGetStringList(&ConfigInfo, "TCPServer");
	StringList	*udpaddrs	=	ConfigGetStringList(&ConfigInfo, "UDPServer");

	const char	*Itr	=	NULL;

	if( AddressChunk_Init(&Addresses) != 0 )
	{
		return -1;
	}

	Itr = StringList_GetNext(tcpaddrs, NULL);
	while( Itr != NULL )
	{
		if( AddressChunk_AddATCPAddress_FromString(&Addresses, Itr) != 0 )
		{
			INFO("Bad address : %s\n", Itr);
		} else {
			DEBUG_FILE("Add TCP address : %s\n", Itr);
		}

		Itr = StringList_GetNext(tcpaddrs, Itr);
	}

	Itr = StringList_GetNext(udpaddrs, NULL);
	while( Itr != NULL )
	{
		if( AddressChunk_AddAUDPAddress_FromString(&Addresses, Itr) != 0 )
		{
			INFO("Bad address : %s\n", Itr);
		} else {
			DEBUG_FILE("Add UDP address : %s\n", Itr);
		}

		Itr = StringList_GetNext(udpaddrs, Itr);
	}

	ParallelQuery = ConfigGetBoolean(&ConfigInfo, "ParallelQuery");
	if( ParallelQuery == TRUE )
	{
		int NumberOfAddr;

		int AddrLen;

		sa_family_t SubFamily;

		struct sockaddr *OneAddr;

		NumberOfAddr = StringList_Count(udpaddrs);
		if( NumberOfAddr <= 0 )
		{
			ERRORMSG("No UDP server specified, cannot use parallel query.\n")
			ParallelQuery = FALSE;
		} else {
			DEBUG_FILE("Enable parallel query.\n");

			AddressChunk_GetOneUDPBySubscript(&Addresses, &ParallelMainFamily, 0);

			if( ParallelMainFamily == AF_INET )
			{
				AddrLen = sizeof(struct sockaddr);

				DEBUG_FILE("Parallel query servers family IPv4.\n");

			} else {
				AddrLen = sizeof(struct sockaddr_in6);

				DEBUG_FILE("Parallel query servers family IPv6.\n");
			}

			Array_Init(&Addresses_Array, AddrLen, NumberOfAddr, FALSE, NULL);

			while( NumberOfAddr != 0 )
			{
				OneAddr = AddressChunk_GetOneUDPBySubscript(&Addresses, &SubFamily, NumberOfAddr - 1);
				if( OneAddr != NULL && SubFamily == ParallelMainFamily )
				{
					Array_PushBack(&Addresses_Array, OneAddr, NULL);
				}

				--NumberOfAddr;
			}
		}
	}

	StringList_Free(tcpaddrs);
	StringList_Free(udpaddrs);

	return LoadDedicatedServer();

}

static sa_family_t GetAddress(ControlHeader		*Header,
							  DNSQuaryProtocol	ProtocolUsed,
							  struct sockaddr	**Addresses_List,
							  int				*NumberOfAddresses,
							  sa_family_t		*Family
							  )
{
	*Addresses_List = AddressChunk_GetDedicated(&Addresses, Family, Header -> RequestingDomain, &(Header -> RequestingDomainHashValue));

	if( *Addresses_List == NULL )
	{
		if( ProtocolUsed == DNS_QUARY_PROTOCOL_UDP && ParallelQuery == TRUE )
		{
			*Addresses_List = (struct sockaddr *)Addresses_Array.Data;
			if( NumberOfAddresses != NULL )
			{
				*NumberOfAddresses = Addresses_Array.Used;
			}
			*Family = ParallelMainFamily;
		} else {
			*Addresses_List = AddressChunk_GetOne(&Addresses, Family, ProtocolUsed);
			if( NumberOfAddresses != NULL )
			{
				*NumberOfAddresses = 1;
			}
		}
	} else {
		if( NumberOfAddresses != NULL )
		{
			*NumberOfAddresses = 1;
		}
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

static BOOL UDPAppendEDNSOpt = FALSE;
static BOOL UDPAntiPollution = FALSE;

void SetUDPAntiPollution(BOOL State)
{
	UDPAntiPollution = State;
}

void SetUDPAppendEDNSOpt(BOOL State)
{
	UDPAppendEDNSOpt = State;
}

#define	IP_MISCELLANEOUS_TYPE_BLOCK			1
#define	IP_MISCELLANEOUS_TYPE_SUBSTITUTE	2
static IpChunk	*IPMiscellaneous = NULL;

static BOOL DoIPMiscellaneous(const char *RequestEntity, const char *Domain, BOOL Block, BOOL Substitute)
{
	int		AnswerCount;

	if( ((DNSHeader *)RequestEntity) -> Flags.ResponseCode != 0 )
	{
		return TRUE;
	}

	AnswerCount = DNSGetAnswerCount(RequestEntity);

	if( AnswerCount > 0 )
	{
		const unsigned char *Answer;
		uint32_t *Data;

		int	ActionType;
		const char *ActionData;

		if( Block == TRUE && UDPAppendEDNSOpt == TRUE && DNSGetAdditionalCount(RequestEntity) <= 0 )
		{
			DomainStatistic_Add(Domain, NULL, STATISTIC_TYPE_POISONED);
			ShowBlockedMessage(Domain, RequestEntity, "False package, discarded");
			return TRUE;
		}

		Answer = (const unsigned char *)DNSGetAnswerRecordPosition(RequestEntity, 1);

		Data = (uint32_t *)DNSGetResourceDataPos(Answer);

		if( Block == TRUE && DNSGetRecordType(Answer) == DNS_TYPE_A && *Answer != 0xC0 )
		{
			if( IPMiscellaneous != NULL )
			{
				if( IpChunk_Find(IPMiscellaneous, *Data, &ActionType, NULL) == TRUE )
				{
					if( ActionType == IP_MISCELLANEOUS_TYPE_BLOCK )
					{
						ShowBlockedMessage(Domain, RequestEntity, "False package, discarded");
					} else {
						ShowBlockedMessage(Domain, RequestEntity, "False package, discarded. And its IP address is not in `UDPBlock_IP'");
					}
				} else {
					ShowBlockedMessage(Domain, RequestEntity, "False package, discarded. And its IP address is not in `UDPBlock_IP'");
				}
			}

			DomainStatistic_Add(Domain, NULL, STATISTIC_TYPE_POISONED);
			return TRUE;
		}

		if( IPMiscellaneous != NULL )
		{
			int					Loop		=	1;
			const unsigned char	*Answer1	=	Answer;
			uint32_t			*Data1		=	Data;

			do
			{
				if( DNSGetRecordType(Answer1) == DNS_TYPE_A && IpChunk_Find(IPMiscellaneous, *Data1, &ActionType, &ActionData) == TRUE )
				{
					switch( ActionType )
					{
						case IP_MISCELLANEOUS_TYPE_BLOCK:
							if( Block == TRUE )
							{
								ShowBlockedMessage(Domain, RequestEntity, "One of the IPs is in blocked list, discarded");
								DomainStatistic_Add(Domain, NULL, STATISTIC_TYPE_POISONED);
								return TRUE;
							}
							break;

						case IP_MISCELLANEOUS_TYPE_SUBSTITUTE:
							memcpy(Data1, ActionData, 4);
							break;

						default:
							break;
					}

				}

				++Loop;

				if( Loop > AnswerCount )
				{
					break;
				}

				Answer1 = (const unsigned char *)DNSGetAnswerRecordPosition(RequestEntity, Loop);
				Data1 = (uint32_t *)DNSGetResourceDataPos(Answer1);

			} while( TRUE );

		}

		return FALSE;
	} else {
		return FALSE;
	}
}

static void SendBack(SOCKET Socket,
					 ControlHeader *Header,
					 QueryContext *Context,
					 int Length,
					 char Protocal,
					 StatisticType Type,
					 BOOL NeededBlock
					 )
{
	char	*RequestEntity = (char *)(Header + 1);
	int32_t	QueryContextNumber;
	QueryContextEntry	*ThisContext;

	DNSGetHostName(RequestEntity,
				   DNSJumpHeader(RequestEntity),
				   Header -> RequestingDomain
				   );

	StrToLower(Header -> RequestingDomain);

	Header -> RequestingDomainHashValue = ELFHash(Header -> RequestingDomain, 0);

	QueryContextNumber = InternalInterface_QueryContextFind(Context, *(uint16_t *)RequestEntity, Header -> RequestingDomainHashValue);
	if( QueryContextNumber >= 0 )
	{
		ThisContext = Bst_GetDataByNumber(Context, QueryContextNumber);

		DomainStatistic_Add(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue), Type);

		if( DoIPMiscellaneous(RequestEntity, Header -> RequestingDomain, NeededBlock, TRUE) == FALSE )
		{
			if( ThisContext -> NeededHeader == TRUE )
			{
				sendto(Socket,
						(const char *)Header,
						Length,
						0,
						(const struct sockaddr *)&(ThisContext -> Context.BackAddress.Addr),
						GetAddressLength(ThisContext -> Context.BackAddress.family)
						);

			} else {
				sendto(Socket,
						RequestEntity,
						Length - sizeof(ControlHeader),
						0,
						(const struct sockaddr *)&(ThisContext -> Context.BackAddress.Addr),
						GetAddressLength(ThisContext -> Context.BackAddress.family)
						);
			}

			InternalInterface_QueryContextRemoveByNumber(Context, QueryContextNumber);
			ShowNormalMassage(ThisContext -> Agent, Header -> RequestingDomain, RequestEntity, Length - sizeof(ControlHeader), Protocal);
			DNSCache_AddItemsToCache(RequestEntity, time(NULL));
		}
	} else {
		/* ShowNormalMassage("Redundant Package", Header -> RequestingDomain, RequestEntity, Length - sizeof(ControlHeader), Protocal); */
	}
}

static void TCPSwepOutput(QueryContextEntry *Entry, int Number)
{
	ShowTimeOutMassage(Entry -> Agent, Entry -> Type, Entry -> Domain, 'T');
	DomainStatistic_Add(Entry -> Domain, &(Entry -> HashValue), STATISTIC_TYPE_REFUSED);

	if( Number == 1 )
	{
		AddressChunk_Advance(&Addresses, DNS_QUARY_PROTOCOL_TCP);
	}
}

int QueryDNSViaTCP(void)
{
	static QueryContext	Context;

	SOCKET	TCPQueryIncomeSocket;
	SOCKET	TCPQueryOutcomeSocket;
	SOCKET	SendBackSocket;

	int		NumberOfQueryBeforeSwep = 0;

	static fd_set	ReadSet, ReadySet;

	static const struct timeval	LongTime = {3600, 0};
	static const struct timeval	ShortTime = {2, 0};

	struct timeval	TimeLimit = LongTime;

	int		MaxFd;

	static char		RequestEntity[2048];
	ControlHeader	*Header = (ControlHeader *)RequestEntity;

	sa_family_t		LastFamily = MainFamily;
	struct sockaddr	*LastAddress = NULL;

	TCPQueryIncomeSocket = InternalInterface_TryOpenLocal(10100, INTERNAL_INTERFACE_TCP_QUERY);
	TCPQueryOutcomeSocket = socket(MainFamily, SOCK_STREAM, IPPROTO_TCP);

	SendBackSocket = InternalInterface_GetSocket(INTERNAL_INTERFACE_UDP_INCOME);

	if( TCPQueryOutcomeSocket == INVALID_SOCKET )
	{
		return -1;
	}

	MaxFd = TCPQueryIncomeSocket > TCPQueryOutcomeSocket ? TCPQueryIncomeSocket : TCPQueryOutcomeSocket;
	FD_ZERO(&ReadSet);
	FD_ZERO(&ReadySet);
	FD_SET(TCPQueryIncomeSocket, &ReadSet);
	FD_SET(TCPQueryOutcomeSocket, &ReadSet);

	InternalInterface_InitQueryContext(&Context);

	while( TRUE )
	{
		ReadySet = ReadSet;

		switch( select(MaxFd + 1, &ReadySet, NULL, NULL, &TimeLimit) )
		{
			case SOCKET_ERROR:
				break;

			case 0:
				if( InternalInterface_QueryContextSwep(&Context, 2, TCPSwepOutput) == TRUE )
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
					int	State;
					sa_family_t	NewFamily;
					struct sockaddr	*NewAddress;
					uint16_t	TCPLength;

					State = recvfrom(TCPQueryIncomeSocket,
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

					GetAddress((ControlHeader *)RequestEntity, DNS_QUARY_PROTOCOL_TCP, &NewAddress, NULL, &NewFamily);
					if( NewFamily != LastFamily || NewAddress != LastAddress || TCPSocketIsHealthy(TCPQueryOutcomeSocket) == FALSE )
					{
						FD_CLR(TCPQueryOutcomeSocket, &ReadSet);

						CLOSE_SOCKET(TCPQueryOutcomeSocket);
						TCPQueryOutcomeSocket = socket(NewFamily, SOCK_STREAM, IPPROTO_TCP);
						if( TCPQueryOutcomeSocket == INVALID_SOCKET )
						{
							LastFamily = AF_UNSPEC;
							break;
						}

						if( connect(TCPQueryOutcomeSocket, NewAddress, GetAddressLength(NewFamily)) != 0 )
						{
							AddressChunk_Advance(&Addresses, DNS_QUARY_PROTOCOL_TCP);
							break;
						}

						LastFamily = NewFamily;
						LastAddress = NewAddress;
						if( TCPQueryOutcomeSocket > MaxFd )
						{
							MaxFd = TCPQueryOutcomeSocket;
						}

						FD_SET(TCPQueryOutcomeSocket, &ReadSet);
					}

					InternalInterface_QueryContextAddUDP(&Context, Header);

					TCPLength = htons(State - sizeof(ControlHeader));
					send(TCPQueryOutcomeSocket, (const char *)&TCPLength, 2, MSG_NOSIGNAL);
					send(TCPQueryOutcomeSocket, RequestEntity + sizeof(ControlHeader), State - sizeof(ControlHeader), MSG_NOSIGNAL);

				} else {
					int	State;
					uint16_t	TCPLength;

					if( recv(TCPQueryOutcomeSocket, (char *)&TCPLength, 2, MSG_NOSIGNAL) < 2 )
					{
						CloseTCPConnection(TCPQueryOutcomeSocket);
						FD_CLR(TCPQueryOutcomeSocket, &ReadSet);
						break;
					}

					TCPLength = ntohs(TCPLength);

					if( TCPLength > sizeof(RequestEntity) - sizeof(ControlHeader) )
					{
						ClearTCPSocketBuffer(TCPQueryOutcomeSocket, TCPLength);
						break;
					}

					State = recv(TCPQueryOutcomeSocket,
								RequestEntity + sizeof(ControlHeader),
								TCPLength,
								MSG_NOSIGNAL
								);

					if( State != TCPLength )
					{
						CloseTCPConnection(TCPQueryOutcomeSocket);
						FD_CLR(TCPQueryOutcomeSocket, &ReadSet);
						break;
					}

					SendBack(SendBackSocket, Header, &Context, State + sizeof(ControlHeader), 'T', STATISTIC_TYPE_TCP, FALSE);
				}
		}
	}
}

static char OptPseudoRecord[] = {
	0x00,
	0x00, 0x29,
	0x05, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00
};

int InitBlockedIP(StringList *l)
{
	const char	*Itr = NULL;
	uint32_t	Ip;

	if( l == NULL )
	{
		return 0;
	}

	if( IPMiscellaneous == NULL )
	{
		IPMiscellaneous = SafeMalloc(sizeof(IpChunk));
		IpChunk_Init(IPMiscellaneous);
	}

	Itr = StringList_GetNext(l, NULL);

	while( Itr != NULL )
	{
		IPv4AddressToNum(Itr, &Ip);

		IpChunk_Add(IPMiscellaneous, Ip, IP_MISCELLANEOUS_TYPE_BLOCK, NULL, 0);

		Itr = StringList_GetNext(l, Itr);
	}

	StringList_Free(l);

	return 0;
}

int InitIPSubstituting(StringList *l)
{
	const char	*Itr = NULL;

	char	Origin_Str[] = "xxx.xxx.xxx.xxx";
	char	Substituted_Str[] = "xxx.xxx.xxx.xxx";

	uint32_t	Origin, Substituted;

	if( l == NULL )
	{
		return 0;
	}

	if( IPMiscellaneous == NULL )
	{
		IPMiscellaneous = SafeMalloc(sizeof(IpChunk));
		IpChunk_Init(IPMiscellaneous);
	}

	Itr = StringList_GetNext(l, NULL);

	while( Itr != NULL )
	{
		sscanf(Itr, "%s %s", Origin_Str, Substituted_Str);

		IPv4AddressToNum(Origin_Str, &Origin);
		IPv4AddressToNum(Substituted_Str, &Substituted);

		IpChunk_Add(IPMiscellaneous, Origin, IP_MISCELLANEOUS_TYPE_SUBSTITUTE, (const char *)&Substituted, 4);

		Itr = StringList_GetNext(l, Itr);
	}

	StringList_Free(l);

	return 0;
}

static void SendQueryViaUDP(SOCKET		Socket,
							const char	*RequestEntity,
							int			EntityLength,
							struct sockaddr	*Addresses_List,
							int			NumberOfAddresses,
							sa_family_t	Family
							)
{
	int		AddrLen = GetAddressLength(Family);

	int		StateOfSending = 0;

	if( UDPAppendEDNSOpt == TRUE && DNSGetAdditionalCount(RequestEntity) == 0 )
	{
		memcpy((char *)RequestEntity + EntityLength, OptPseudoRecord, sizeof(OptPseudoRecord));

		DNSSetAdditionalCount(RequestEntity, 1);

		EntityLength += sizeof(OptPseudoRecord);
	}

	while( NumberOfAddresses != 0 )
	{
		StateOfSending |= (sendto(Socket, RequestEntity, EntityLength, 0, Addresses_List, AddrLen) > 0);

		Addresses_List = (struct sockaddr *)(((char *)Addresses_List) + AddrLen);

		--NumberOfAddresses;
	}
}

static void UDPSwepOutput(QueryContextEntry *Entry, int Number)
{
	ShowTimeOutMassage(Entry -> Agent, Entry -> Type, Entry -> Domain, 'U');
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
	static const struct timeval	ShortTime = {2, 0};

	struct timeval	TimeLimit = LongTime;

	int		MaxFd;

	sa_family_t		LastFamily = ParallelMainFamily;

	static char		RequestEntity[2048];
	ControlHeader	*Header = (ControlHeader *)RequestEntity;

	UDPQueryIncomeSocket =	InternalInterface_TryOpenLocal(10125, INTERNAL_INTERFACE_UDP_QUERY);
	UDPQueryOutcomeSocket = InternalInterface_OpenASocket(ParallelMainFamily, NULL);

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
					InternalInterface_QueryContextSwep(&Context, 2, UDPSwepOutput);
					NumberOfQueryBeforeSwep = 0;
				}

				if( FD_ISSET(UDPQueryIncomeSocket, &ReadySet) )
				{
					int State;
					struct sockaddr	*NewAddress;
					int	NumberOfAddresses;
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

					GetAddress((ControlHeader *)RequestEntity, DNS_QUARY_PROTOCOL_UDP, &NewAddress, &NumberOfAddresses, &NewFamily);

					if( NewFamily != LastFamily )
					{
						FD_CLR(UDPQueryOutcomeSocket, &ReadSet);
						CLOSE_SOCKET(UDPQueryOutcomeSocket);
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
									NumberOfAddresses,
									NewFamily
									);

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

					SendBack(SendBackSocket, Header, &Context, State + sizeof(ControlHeader), 'U', STATISTIC_TYPE_UDP, UDPAntiPollution);
				}
			break;
		}
	}
}

int ProbeFakeAddresses(const char	*ServerAddress,
					   const char	*RequestingDomain,
					   StringList	*out
					   )
{
	char	RequestEntity[384] = {
		00, 00, /* QueryIdentifier */
		01, 00, /* Flags */
		00, 01, /* QuestionCount */
		00, 00, /* AnswerCount */
		00, 00, /* NameServerCount */
		00, 00, /* AdditionalCount */
		/* Header end */
	};

	struct sockaddr_in	PeerAddr;
	SOCKET	Sock;

	int		NumberOfAddresses = 0;

	int		RequestLength;

	int		AddrLen = sizeof(struct sockaddr);
	char	NewlyReceived[2048];

	if( DNSGenQuestionRecord(RequestEntity + 12, sizeof(RequestEntity) - 12, RequestingDomain, DNS_TYPE_NS, DNS_CLASS_IN) == 0 )
	{
		return -1;
	}

	FILL_ADDR4(PeerAddr, AF_INET, ServerAddress, 53);

	Sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if( Sock == INVALID_SOCKET )
	{
		return -1;
	}

	SetSocketRecvTimeLimit(Sock, 2000);

	RequestLength = 12 + strlen(RequestingDomain) + 2 + 4;

	*(uint16_t *)RequestEntity = rand();

	if( sendto(Sock, RequestEntity, RequestLength, 0, (struct sockaddr *)&PeerAddr, AddrLen) == 0 )
	{
		CLOSE_SOCKET(Sock);
		return -1;
	}

	while( TRUE )
	{
		if( recvfrom(Sock, NewlyReceived, sizeof(NewlyReceived), 0, NULL, NULL) <= 0 )
		{
			break;
		}

		if( *(uint16_t *)RequestEntity != *(uint16_t *)NewlyReceived )
		{
			continue;
		}

		if( ((DNSHeader *)NewlyReceived) -> Flags.ResponseCode != 0 )
		{
			continue;
		}

		if( DNSGetAnswerCount(NewlyReceived) > 0 )
		{
			const char *FirstAnswer;

			FirstAnswer = DNSGetAnswerRecordPosition(NewlyReceived, 1);

			if( DNSGetRecordType(FirstAnswer) == DNS_TYPE_A )
			{
				NumberOfAddresses += GetHostsByRaw(NewlyReceived, out);

				continue;
			} else {
				break;
			}
		}

		if( DNSGetNameServerCount(NewlyReceived) == 0 && DNSGetAdditionalCount(NewlyReceived) == 0 )
		{
			continue;
		}

		break;
	}

	ClearSocketBuffer(Sock);

	CLOSE_SOCKET(Sock);
	return NumberOfAddresses;
}

int TestServer(struct TestServerArguments *Args)
{
	const char *RequestingDomain = "www.google.com";

	char	RequestEntity[384] = {
		00, 00, /* QueryIdentifier */
		01, 00, /* Flags */
		00, 01, /* QuestionCount */
		00, 00, /* AnswerCount */
		00, 00, /* NameServerCount */
		00, 00, /* AdditionalCount */
		/* Header end */
	};

	Address_Type	PeerAddr;
	SOCKET	Sock;

	sa_family_t	AddressFamily;

	int		RequestLength;

	char	NewlyReceived[2048];

	Args -> ServerAddress = GoToNextNonSpace(Args -> ServerAddress);
	if( strchr(Args -> ServerAddress, ':') != NULL && *(Args -> ServerAddress) != '[' )
	{
		char ServerAddress_Regulated[LENGTH_OF_IPV6_ADDRESS_ASCII + 3];
		sprintf(ServerAddress_Regulated, "[%s]", Args -> ServerAddress);

		AddressFamily = AddressList_ConvertToAddressFromString(&PeerAddr, ServerAddress_Regulated, 53);
	} else {
		AddressFamily = AddressList_ConvertToAddressFromString(&PeerAddr, Args -> ServerAddress, 53);
	}

	if( AddressFamily == AF_UNSPEC )
	{
		return -1;
	}

	Sock = socket(AddressFamily, SOCK_DGRAM, IPPROTO_UDP);
	if( Sock == INVALID_SOCKET )
	{
		return -1;
	}

	SetSocketRecvTimeLimit(Sock, 2000);

	if( DNSGenQuestionRecord(RequestEntity + 12, sizeof(RequestEntity) - 12, RequestingDomain, DNS_TYPE_A, DNS_CLASS_IN) == 0 )
	{
		return -1;
	}

	RequestLength = 12 + strlen(RequestingDomain) + 2 + 4;

	*(Args -> Counter) = 0;

	while( TRUE )
	{
		*(uint16_t *)RequestEntity = rand();

		if( sendto(Sock, RequestEntity, RequestLength, 0, (struct sockaddr *)&(PeerAddr.Addr), GetAddressLength(AddressFamily)) == 0 )
		{
			CLOSE_SOCKET(Sock);
			return -1;
		}

		if( recvfrom(Sock, NewlyReceived, sizeof(NewlyReceived), 0, NULL, NULL) <= 0 )
		{
			return -2;
		}

		++(*(Args -> Counter));
	}

	return 0;
}

int SetSocketWait(SOCKET sock, BOOL Wait)
{
	return setsockopt(sock, SOL_SOCKET, SO_DONTLINGER, (const char *)&Wait, sizeof(BOOL));
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











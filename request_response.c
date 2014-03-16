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
	int NumberOfAddr;

	Address_Type	Address;

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

	NumberOfAddr = StringList_Count(udpaddrs);
	if( NumberOfAddr <= 0 )
	{
		return -1;
	}

	Itr = StringList_GetNext(udpaddrs, NULL);
	ParallelMainFamily = GetAddressFamily(Itr);

	Array_Init(&Addresses_Array, GetAddressLength(ParallelMainFamily), NumberOfAddr, FALSE, NULL);

	while( Itr != NULL )
	{
		if( AddressList_ConvertToAddressFromString(&Address, Itr, 53) == ParallelMainFamily )
		{
			Array_PushBack(&Addresses_Array, &(Address.Addr), NULL);
		}

		Itr = StringList_GetNext(udpaddrs, Itr);
	}

	StringList_Free(tcpaddrs);
	StringList_Free(udpaddrs);

	return LoadDedicatedServer();

}

sa_family_t GetTCPAddress(struct sockaddr **Addresses_List, ControlHeader *Header)
{
	sa_family_t	ret = MainFamily;

	*Addresses_List = AddressChunk_GetDedicated(&Addresses, &ret, Header -> RequestingDomain, &(Header -> RequestingDomainHashValue));

	if( *Addresses_List == NULL )
	{
		*Addresses_List = AddressChunk_GetOne(&Addresses, &ret, DNS_QUARY_PROTOCOL_TCP);
	}

	return ret;
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

static IpChunk	*BlockedIP = NULL;

static BOOL WouldBeBlock(const char *RequestEntity, const char *Domain)
{
	int		AnswerCount;

	if( ((DNSHeader *)RequestEntity) -> Flags.ResponseCode != 0 )
	{
		return TRUE;
	}

	AnswerCount = DNSGetAnswerCount(RequestEntity);

	if( UDPAntiPollution == TRUE && AnswerCount > 0 )
	{
		const unsigned char *Answer;
		uint32_t *Data;

		if( UDPAppendEDNSOpt == TRUE && DNSGetAdditionalCount(RequestEntity) <= 0 )
		{
			DomainStatistic_Add(Domain, NULL, STATISTIC_TYPE_POISONED);
			return TRUE;
		}

		Answer = (const unsigned char *)DNSGetAnswerRecordPosition(RequestEntity, 1);

		Data = (uint32_t *)DNSGetResourceDataPos(Answer);

		if( DNSGetRecordType(Answer) == DNS_TYPE_A && *Answer != 0xC0 )
		{
			if( BlockedIP != NULL && IpChunk_Find(BlockedIP, *Data) == TRUE )
			{
				ShowBlockedMessage(Domain, RequestEntity, "False package, discarded. And its IP address is not in `UDPBlock_IP'");
			} else {
				ShowBlockedMessage(Domain, RequestEntity, "False package, discarded");
			}

			DomainStatistic_Add(Domain, NULL, STATISTIC_TYPE_POISONED);
			return TRUE;
		}

		if( BlockedIP != NULL )
		{
			int					Loop		=	1;
			const unsigned char	*Answer1	=	Answer;
			uint32_t			*Data1		=	Data;

			do
			{
				if( DNSGetRecordType(Answer1) == DNS_TYPE_A && IpChunk_Find(BlockedIP, *Data1) == TRUE )
				{
					ShowBlockedMessage(Domain, RequestEntity, "Containing blocked ip, discarded");
					DomainStatistic_Add(Domain, NULL, STATISTIC_TYPE_POISONED);
					return TRUE;
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

static void SendBack(SOCKET Socket, ControlHeader *Header, QueryContext *Context, int Length, char Protocal, BOOL NeededBlock)
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

		if( NeededBlock == FALSE || WouldBeBlock(RequestEntity, Header -> RequestingDomain) == FALSE )
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

static void TCPSwepOutput(QueryContextEntry *Entry)
{
	ShowTimeOutMassage(Entry -> Agent, Entry -> Type, Entry -> Domain, 'T');
	DomainStatistic_Add(Entry -> Domain, &(Entry -> HashValue), STATISTIC_TYPE_REFUSED);
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

					NewFamily = GetTCPAddress(&NewAddress, Header);
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

					DomainStatistic_Add(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue), STATISTIC_TYPE_TCP);

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

					SendBack(SendBackSocket, Header, &Context, State + sizeof(ControlHeader), 'T', FALSE);
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

	BlockedIP = SafeMalloc(sizeof(IpChunk));
	IpChunk_Init(BlockedIP);

	Itr = StringList_GetNext(l, NULL);

	while( Itr != NULL )
	{
		IPv4AddressToNum(Itr, &Ip);

		IpChunk_Add(BlockedIP, Ip);

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

static void UDPSwepOutput(QueryContextEntry *Entry)
{
	ShowTimeOutMassage(Entry -> Agent, Entry -> Type, Entry -> Domain, 'U');
	DomainStatistic_Add(Entry -> Domain, &(Entry -> HashValue), STATISTIC_TYPE_REFUSED);
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

					NewAddress = AddressChunk_GetDedicated(&Addresses, &NewFamily, Header -> RequestingDomain, &(Header -> RequestingDomainHashValue));
					if( NewAddress == NULL )
					{
						NewAddress = (struct sockaddr *)Addresses_Array.Data;
						NumberOfAddresses = Addresses_Array.Used;
						NewFamily = ParallelMainFamily;
					} else {
						NumberOfAddresses = 1;
					}

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

					DomainStatistic_Add(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue), STATISTIC_TYPE_UDP);
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

					SendBack(SendBackSocket, Header, &Context, State + sizeof(ControlHeader), 'U', TRUE);
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











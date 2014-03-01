#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "querydnslistenudp.h"
#include "querydnsbase.h"
#include "dnsrelated.h"
#include "dnsparser.h"
#include "common.h"
#include "utils.h"
#include "stringlist.h"
#include "excludedlist.h"
#include "internalsocket.h"

/* Variables */
static BOOL			Inited = FALSE;

/*
static MutexHandle	ListenMutex;
static EFFECTIVE_LOCK	LockOfSendBack;
*/
static SOCKET		UDPIncomeSocket;

static SOCKET		UDPOutcomeSocket;

static int			MaximumMessageSize;

static int			RefusingResponseCode = 0;

#define _SendTo(...)	EFFECTIVE_LOCK_GET(LockOfSendBack); \
						sendto(__VA_ARGS__); \
						EFFECTIVE_LOCK_RELEASE(LockOfSendBack);

/* Functions */
int QueryDNSListenUDPInit(void)
{
	const char	*LocalAddr = ConfigGetRawString(&ConfigInfo, "LocalInterface");
	int			LocalPort = ConfigGetInt32(&ConfigInfo, "LocalPort");

	RefusingResponseCode = ConfigGetInt32(&ConfigInfo, "RefusingResponseCode");

	UDPIncomeSocket = InternalInterface_Open2(LocalAddr, LocalPort, INTERNAL_INTERFACE_UDP_INCOME);

	if( UDPIncomeSocket == INVALID_SOCKET )
	{
		ShowFatalMessage("Creating UDP socket failed.", GET_LAST_ERROR());
		return -1;
	}

	MainFamily = InternalInterface_GetAddress(INTERNAL_INTERFACE_UDP_INCOME, NULL);

	UDPOutcomeSocket = socket(MainFamily, SOCK_DGRAM, IPPROTO_UDP);
	if( UDPOutcomeSocket == INVALID_SOCKET )
	{
		ShowFatalMessage("Creating UDP outcome socket failed.", GET_LAST_ERROR());
		return -1;
	}
/*
	CREATE_MUTEX(ListenMutex);
	EFFECTIVE_LOCK_INIT(LockOfSendBack);
*/
	Inited = TRUE;

	return 0;
}

static int Query(char *Content, int ContentLength, int BufferLength, Address_Type *ClientAddr)
{
	int State;

	ControlHeader	*Header = (ControlHeader *)Content;

	char *RequestEntity = Content + sizeof(ControlHeader);

	if( MainFamily == AF_INET )
	{
		strcpy(Header -> Agent, inet_ntoa(ClientAddr -> Addr.Addr4.sin_addr));
	} else {
		IPv6AddressToAsc(&(ClientAddr -> Addr.Addr6.sin6_addr), Header -> Agent);
	}

	memcpy(&(Header -> BackAddress), ClientAddr, sizeof(Address_Type));

	Header -> RequestingDomain[0] = '\0';
	DNSGetHostName(RequestEntity,
				   DNSJumpHeader(RequestEntity),
				   Header -> RequestingDomain
				   );

	StrToLower(Header -> RequestingDomain);

	Header -> RequestingType =
		(DNSRecordType)DNSGetRecordType(DNSJumpHeader(RequestEntity));

	Header -> RequestingDomainHashValue = ELFHash(Header -> RequestingDomain, 0);

	State = QueryBase(Content, ContentLength, BufferLength, UDPOutcomeSocket);

	switch( State )
	{
		case QUERY_RESULT_SUCESS:
			return 0;
			break;

		case QUERY_RESULT_DISABLE:
			((DNSHeader *)(RequestEntity)) -> Flags.Direction = 1;
			((DNSHeader *)(RequestEntity)) -> Flags.RecursionAvailable = 1;
			((DNSHeader *)(RequestEntity)) -> Flags.ResponseCode = RefusingResponseCode;
			if( MainFamily == AF_INET )
			{
				sendto(UDPIncomeSocket,
						RequestEntity,
						ContentLength - sizeof(ControlHeader),
						0,
						(struct sockaddr *)&(ClientAddr -> Addr.Addr4),
						sizeof(struct sockaddr)
						);
			} else {
				sendto(UDPIncomeSocket,
						RequestEntity,
						ContentLength - sizeof(ControlHeader),
						0,
						(struct sockaddr *)&(ClientAddr -> Addr.Addr6),
						sizeof(struct sockaddr_in6)
						);
			}
			return -1;
			break;

		case QUERY_RESULT_ERROR:
			return -1;
			break;

		default: /* Cache */
			if( MainFamily == AF_INET )
			{
				sendto(UDPIncomeSocket,
						RequestEntity,
						State,
						0,
						(struct sockaddr *)&(ClientAddr -> Addr.Addr4),
						sizeof(struct sockaddr)
						);
			} else {
				sendto(UDPIncomeSocket,
						RequestEntity,
						State,
						0,
						(struct sockaddr *)&(ClientAddr -> Addr.Addr6),
						sizeof(struct sockaddr_in6)
						);
			}
			return 0;
			break;
	}
}

static int QueryDNSListenUDP(void)
{
	socklen_t		AddrLen;

	Address_Type	ClientAddr;

	int				State;

	static char		RequestEntity[2048];
	ControlHeader	*Header = (ControlHeader *)RequestEntity;

	InternalInterface_InitControlHeader(Header);
	Header -> NeededHeader = FALSE;

	ClientAddr.family = MainFamily;

	/* Listen and accept requests */
	while(TRUE)
	{
		memset(&(ClientAddr.Addr), 0, sizeof(ClientAddr.Addr));

		if( MainFamily == AF_INET )
		{
			AddrLen = sizeof(struct sockaddr);
			State = recvfrom(UDPIncomeSocket,
							 RequestEntity + sizeof(ControlHeader),
							 sizeof(RequestEntity) - sizeof(ControlHeader),
							 0,
							 (struct sockaddr *)&(ClientAddr.Addr.Addr4),
							 &AddrLen
							 );

		} else {
			AddrLen = sizeof(struct sockaddr_in6);
			State = recvfrom(UDPIncomeSocket,
							 RequestEntity + sizeof(ControlHeader),
							 sizeof(RequestEntity) - sizeof(ControlHeader),
							 0,
							 (struct sockaddr *)&(ClientAddr.Addr.Addr6),
							 &AddrLen
							 );

		}

		if(State < 1)
		{
			if( ErrorMessages == TRUE )
			{
				int		ErrorNum = GET_LAST_ERROR();
				char	ErrorMessage[320];

				ErrorMessage[0] ='\0';

				GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));
				if( MainFamily == AF_INET )
				{
					printf("An error occured while receiving from %s : %d : %s .\n",
						   inet_ntoa(ClientAddr.Addr.Addr4.sin_addr),
						   ErrorNum,
						   ErrorMessage
						   );
				} else {
					char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

					IPv6AddressToAsc(&(ClientAddr.Addr.Addr6.sin6_addr), Addr);

					printf("An error occured while receiving from %s : %d : %s .\n",
						   Addr,
						   ErrorNum,
						   ErrorMessage
						   );

				}
			}
			continue;
		}

		Query(RequestEntity, State + sizeof(ControlHeader), sizeof(RequestEntity), &ClientAddr);

	}

	return 0;
}

void QueryDNSListenUDPStart(void)
{
	ThreadHandle t;

	CREATE_THREAD(QueryDNSListenUDP, NULL, t);
	DETACH_THREAD(t);
}

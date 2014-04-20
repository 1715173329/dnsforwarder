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

static SOCKET		UDPIncomeSocket;

static SOCKET		UDPOutcomeSocket;

static int			MaximumMessageSize;

static int			RefusingResponseCode = 0;

/* Functions */
int QueryDNSListenUDPInit(ConfigFileInfo *ConfigInfo)
{
	RefusingResponseCode = ConfigGetInt32(ConfigInfo, "RefusingResponseCode");
	UDPIncomeSocket = InternalInterface_Open2(MAIN_WORKING_ADDRESS, MAIN_WORKING_PORT, INTERNAL_INTERFACE_UDP_INCOME);
	if( UDPIncomeSocket == INVALID_SOCKET )
	{
		ShowFatalMessage("Creating UDP socket failed.", GET_LAST_ERROR());
		return -1;
	} else {
		INFO("UDP socket %s:%d created.\n", MAIN_WORKING_ADDRESS, MAIN_WORKING_PORT);
	}

	InternalInterface_GetAddress(INTERNAL_INTERFACE_UDP_INCOME, NULL);
	UDPOutcomeSocket = socket(MAIN_FAMILY, SOCK_DGRAM, IPPROTO_UDP);
	if( UDPOutcomeSocket == INVALID_SOCKET )
	{
		ShowFatalMessage("Creating UDP outcome socket failed.", GET_LAST_ERROR());
		return -1;
	}

	Inited = TRUE;

	return 0;
}

static int Query(char *Content, int ContentLength, int BufferLength, Address_Type *ClientAddr)
{
	int SendBackLength = 0;
	int ret = 0;

	int State;

	ControlHeader	*Header			=	(ControlHeader *)Content;
	char			*RequestEntity	=	Content + sizeof(ControlHeader);

	if( (Header + 1) -> _Pad == CONTROLHEADER__PAD )
	{
		Content += sizeof(ControlHeader);
		ContentLength -= sizeof(ControlHeader);
		BufferLength -= sizeof(ControlHeader);
		Header += 1;
		RequestEntity += sizeof(ControlHeader);
	} else {
		if( MAIN_FAMILY == AF_INET )
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
	}

	State = QueryBase(Content, ContentLength, BufferLength, UDPOutcomeSocket);
	switch( State )
	{
		case QUERY_RESULT_SUCESS:
			ret = 0;
			break;

		case QUERY_RESULT_DISABLE:
			((DNSHeader *)(RequestEntity)) -> Flags.Direction = 1;
			((DNSHeader *)(RequestEntity)) -> Flags.RecursionAvailable = 1;
			((DNSHeader *)(RequestEntity)) -> Flags.ResponseCode = RefusingResponseCode;
			SendBackLength = ContentLength - sizeof(ControlHeader);
			ret = -1;
			break;

		case QUERY_RESULT_ERROR:
			ret = -1;
			break;

		default: /* Cache */
			SendBackLength = State;
			ret = 0;
			break;
	}

	if( SendBackLength > 0 )
	{
		if( Header -> NeededHeader == TRUE )
		{
			SendBackLength += sizeof(ControlHeader);
			RequestEntity -= sizeof(ControlHeader);
		}

		sendto(UDPIncomeSocket,
			   RequestEntity,
			   SendBackLength,
			   0,
			   (struct sockaddr *)&(ClientAddr -> Addr),
			   GetAddressLength(MAIN_FAMILY)
			   );
	}

	return ret;
}

static int QueryDNSListenUDP(void)
{
	socklen_t		AddrLen;

	Address_Type	ClientAddr;

	int				State;

	static char		RequestEntity[2048 + 2 * sizeof(ControlHeader)];
	ControlHeader	*Header = (ControlHeader *)RequestEntity;

	InternalInterface_InitControlHeader(Header);
	Header -> NeededHeader = FALSE;
	ClientAddr.family = MAIN_FAMILY;

	/* Listen and accept requests */
	while(TRUE)
	{
		memset(&(ClientAddr.Addr), 0, sizeof(ClientAddr.Addr));

		if( MAIN_FAMILY == AF_INET )
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
				if( MAIN_FAMILY == AF_INET )
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

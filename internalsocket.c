#include <string.h>
#include "internalsocket.h"
#include "addresslist.h"
#include "querydnsbase.h"
#include "dnsparser.h"
#include "utils.h"

int INTERNAL_INTERFACE_PRIMARY;
int INTERNAL_INTERFACE_SECONDARY;

sa_family_t	MAIN_FAMILY = AF_UNSPEC;
const char *MAIN_WORKING_ADDRESS = NULL;
int			MAIN_WORKING_PORT = -1;

static Address_Type			LocalWorkingAddress;

static InternalInterface	Interfaces[7];

int InternalInterface_Init(int PrimaryProtocal, const char *WorkingAddress, int Port)
{
	int loop;

	for( loop = 0; loop != 7; ++loop )
	{
		Interfaces[loop].Socket = INVALID_SOCKET;
	}

    if( PrimaryProtocal == DNS_QUARY_PROTOCOL_UDP )
    {
		INTERNAL_INTERFACE_PRIMARY = INTERNAL_INTERFACE_UDP_QUERY;
		INTERNAL_INTERFACE_SECONDARY = INTERNAL_INTERFACE_TCP_QUERY;
    } else {
		INTERNAL_INTERFACE_PRIMARY = INTERNAL_INTERFACE_TCP_QUERY;
		INTERNAL_INTERFACE_SECONDARY = INTERNAL_INTERFACE_UDP_QUERY;
    }

    MAIN_FAMILY = AddressList_ConvertToAddressFromString(&LocalWorkingAddress, WorkingAddress, Port);
    if( MAIN_FAMILY == AF_UNSPEC )
    {
		return -1;
    }

    MAIN_WORKING_ADDRESS = WorkingAddress;
	MAIN_WORKING_PORT = Port;


	if( MAIN_FAMILY == AF_INET )
	{
		if( strncmp("0.0.0.0", MAIN_WORKING_ADDRESS, 7) == 0 )
		{
			AddressList_ConvertToAddressFromString(&(Interfaces[INTERNAL_INTERFACE_UDP_LOOPBACK_LOCAL].Address), "127.0.0.1", MAIN_WORKING_PORT);
		} else {
			AddressList_ConvertToAddressFromString(&(Interfaces[INTERNAL_INTERFACE_UDP_LOOPBACK_LOCAL].Address), MAIN_WORKING_ADDRESS, MAIN_WORKING_PORT);
		}
	} else {
		if( memcmp(&(LocalWorkingAddress.Addr.Addr6.sin6_addr), "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0", 16) == 0 )
		{
			AddressList_ConvertToAddressFromString(&(Interfaces[INTERNAL_INTERFACE_UDP_LOOPBACK_LOCAL].Address), "[::1]", MAIN_WORKING_PORT);
		} else {
			AddressList_ConvertToAddressFromString(&(Interfaces[INTERNAL_INTERFACE_UDP_LOOPBACK_LOCAL].Address), MAIN_WORKING_ADDRESS, MAIN_WORKING_PORT);
		}
	}

	/* In actual, we won't use this socket, so it's no harm to be zero. */
	Interfaces[INTERNAL_INTERFACE_UDP_LOOPBACK_LOCAL].Socket = 0;

	return 0;
}

SOCKET InternalInterface_OpenASocket(sa_family_t Family, struct sockaddr *Address)
{
	SOCKET ret = socket(Family, SOCK_DGRAM, IPPROTO_UDP);

	if( ret == INVALID_SOCKET )
	{
		return INVALID_SOCKET;
	}

	if( Address != NULL && bind(ret, Address, GetAddressLength(Family)) != 0 )
	{
		int	OriginalErrorCode;

		OriginalErrorCode = GET_LAST_ERROR();
		CLOSE_SOCKET(ret);
		SET_LAST_ERROR(OriginalErrorCode);

		return INVALID_SOCKET;
	}

	return ret;
}

SOCKET InternalInterface_Open(const char *AddressPort, InternalInterfaceType Type, int DefaultPort)
{
	sa_family_t	Family = AddressList_ConvertToAddressFromString(&(Interfaces[Type].Address), AddressPort, DefaultPort);

	if( Family == AF_UNSPEC )
	{
		return -1;
	}

	Interfaces[Type].Socket = InternalInterface_OpenASocket(Family, (struct sockaddr *)&(Interfaces[Type].Address));

	return Interfaces[Type].Socket;
}

SOCKET InternalInterface_Open2(const char *Address, int Port, InternalInterfaceType Type)
{
	return InternalInterface_Open(Address, Type, Port);
}

SOCKET InternalInterface_TryBindAddress(const char *Address_Str, int Port, Address_Type *Address)
{
	int MaxTime = 10000;

	Address_Type Address1;
	SOCKET ret;

	do {
		AddressList_ConvertToAddressFromString(&Address1, Address_Str, Port);
		ret = InternalInterface_OpenASocket(MAIN_FAMILY, (struct sockaddr *)&(Address1.Addr));

		++Port;
		--MaxTime;
	} while( ret == INVALID_SOCKET && MaxTime > 0 );

	if( ret == INVALID_SOCKET )
	{
		return INVALID_SOCKET;
	} else {
		if( Address != NULL )
		{
			memcpy(Address, &Address1, sizeof(Address_Type));
		}

		return ret;
	}
}

SOCKET InternalInterface_TryBindLocal(int Port, Address_Type *Address)
{
	const char	*LocalAddress;

	if( MAIN_FAMILY == AF_INET )
	{
		LocalAddress = "127.0.0.1";
	} else {
		LocalAddress = "[::1]";
	}

	return InternalInterface_TryBindAddress(LocalAddress, Port, Address);
}

SOCKET InternalInterface_TryOpenLocal(int Port, InternalInterfaceType Type)
{
	Interfaces[Type].Socket = InternalInterface_TryBindLocal(Port, &(Interfaces[Type].Address));

	return Interfaces[Type].Socket;
}

SOCKET InternalInterface_OpenTCP(const char *AddressPort, InternalInterfaceType Type, int DefaultPort)
{
	sa_family_t	Family = AddressList_ConvertToAddressFromString(&(Interfaces[Type].Address), AddressPort, DefaultPort);

	if( Family == AF_UNSPEC )
	{
		return -1;
	}

	Interfaces[Type].Socket = socket(Family, SOCK_STREAM, IPPROTO_TCP);

	if( Interfaces[Type].Socket == INVALID_SOCKET )
	{
		return INVALID_SOCKET;
	}

	if(	bind(Interfaces[Type].Socket, (struct sockaddr*)&(Interfaces[Type].Address.Addr), GetAddressLength(Family)) != 0 )
	{
		return INVALID_SOCKET;
	}

	if( listen(Interfaces[Type].Socket, 16) == SOCKET_ERROR )
	{
		return INVALID_SOCKET;
	}

	return Interfaces[Type].Socket;
}

SOCKET InternalInterface_GetSocket(InternalInterfaceType Type)
{
	return Interfaces[Type].Socket;
}

sa_family_t InternalInterface_GetAddress(InternalInterfaceType Type, struct sockaddr **Out)
{
	if( Interfaces[Type].Socket == INVALID_SOCKET )
	{
		ERRORMSG("A bug Hitted. InternalInterface_GetAddress()\n");
		return AF_UNSPEC;
	}

	if( Out != NULL )
	{
		*Out = (struct sockaddr *)&(Interfaces[Type].Address.Addr);
	}

	return Interfaces[Type].Address.family;
}

Address_Type *InternalInterface_GetAddress_Union(InternalInterfaceType Type)
{
	if( Interfaces[Type].Socket == INVALID_SOCKET )
	{
		return NULL;
	}

	return &(Interfaces[Type].Address);
}

int InternalInterface_SendTo(InternalInterfaceType Type, SOCKET ThisSocket, char *Content, int ContentLength)
{
	struct sockaddr	*Address = NULL;
	sa_family_t	Family;

	Family = InternalInterface_GetAddress(Type, &Address);

	return sendto(ThisSocket, Content, ContentLength, 0, Address, GetAddressLength(Family));
}

void InternalInterface_InitControlHeader(ControlHeader *Header)
{
	Header -> _Pad = CONTROLHEADER__PAD;
}

static int QueryContextCompare(const QueryContextEntry *_1, const QueryContextEntry *_2)
{
	if( _1 -> Identifier != _2 -> Identifier )
	{
		return (int)(_1 -> Identifier) - (int)(_2 -> Identifier);
	} else {
		return (_1 -> HashValue) - (int)(_2 -> HashValue);
	}
}

int InternalInterface_InitQueryContext(QueryContext *Context)
{
	return Bst_Init(Context, NULL, sizeof(QueryContextEntry), (int (*)(const void *, const void *))QueryContextCompare);
}

int InternalInterface_QueryContextAddUDP(QueryContext *Context, ControlHeader *Header)
{
	const char *RequestingEntity = (const char *)(Header + 1);
	QueryContextEntry	New;

	New.Identifier = *(uint16_t *)RequestingEntity;
	New.HashValue = Header -> RequestingDomainHashValue;

	New.TimeAdd = time(NULL);
	New.NeededHeader = Header -> NeededHeader;
	strcpy(New.Agent, Header -> Agent);
	New.Type = Header -> RequestingType;
	strcpy(New.Domain, Header -> RequestingDomain);

	if( DNSGetAdditionalCount(RequestingEntity) > 0 )
	{
		New.EDNSEnabled = TRUE;
	} else {
		New.EDNSEnabled = FALSE;
	}

	memcpy(&(New.Context.BackAddress), &(Header -> BackAddress), sizeof(Address_Type));

	return Bst_Add(Context, &New);
}

int InternalInterface_QueryContextAddTCP(QueryContext *Context, ControlHeader *Header, SOCKET Socket)
{
	const char *RequestingEntity = (const char *)(Header + 1);
	QueryContextEntry	New;

	New.Identifier = *(uint16_t *)RequestingEntity;
	New.HashValue = Header -> RequestingDomainHashValue;

	New.TimeAdd = time(NULL);
	New.NeededHeader = Header -> NeededHeader;
	strcpy(New.Agent, Header -> Agent);

	New.Type = Header -> RequestingType;
	strcpy(New.Domain, Header -> RequestingDomain);

	if( DNSGetAdditionalCount(RequestingEntity) > 0 )
	{
		New.EDNSEnabled = TRUE;
	} else {
		New.EDNSEnabled = FALSE;
	}

	New.Context.Socket = Socket;

	return Bst_Add(Context, &New);
}

int InternalInterface_QueryContextAddHosts(QueryContext *Context, ControlHeader *Header, uint32_t Identifier, int32_t HashValue)
{
	const char *RequestingEntity = (const char *)(Header + 1);
	QueryContextEntry	New;

	New.Identifier = Identifier;
	New.HashValue = HashValue;

	New.TimeAdd = time(NULL);
	New.NeededHeader = Header -> NeededHeader;
	strcpy(New.Agent, Header -> Agent);

	if( DNSGetAdditionalCount(RequestingEntity) > 0 )
	{
		New.EDNSEnabled = TRUE;
	} else {
		New.EDNSEnabled = FALSE;
	}

	memcpy(&(New.Context.Hosts.BackAddress), &(Header -> BackAddress), sizeof(Address_Type));
	New.Context.Hosts.Identifier = *(uint16_t *)(Header + 1);
	New.Context.Hosts.HashValue = Header -> RequestingDomainHashValue;

	New.Type = Header -> RequestingType;
	strcpy(New.Domain, Header -> RequestingDomain);

	return Bst_Add(Context, &New);
}

int32_t InternalInterface_QueryContextFind(QueryContext *Context, uint32_t Identifier, int32_t HashValue)
{
	QueryContextEntry	Key;

	Key.Identifier = Identifier;
	Key.HashValue = HashValue;

	return Bst_Search(Context, &Key, NULL);
}

void InternalInterface_QueryContextRemove(QueryContext *Context, uint32_t Identifier, int32_t HashValue)
{
	int32_t NodeNumber;

	NodeNumber = InternalInterface_QueryContextFind(Context, Identifier, HashValue);

	if( NodeNumber > 0 )
	{
		Bst_Delete_ByNumber(Context, NodeNumber);
	}
}

BOOL InternalInterface_QueryContextSwep(QueryContext *Context, time_t TimeOut, void (*OutputFunction)(QueryContextEntry *, int))
{
	int32_t Start = -1;
	int		Number = 1;

	QueryContextEntry	*Entry;

	time_t	Now = time(NULL);

	Entry = Bst_Enum(Context, &Start);
	while( Entry != NULL )
	{
		if( Now - Entry -> TimeAdd > TimeOut )
		{
			if( OutputFunction != NULL )
			{
				OutputFunction(Entry, Number);
			}
			Bst_Delete_ByNumber(Context, Start);

			++Number;
		}

		Entry = Bst_Enum(Context, &Start);
	}

	return Bst_IsEmpty(Context);
}

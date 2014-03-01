#include "internalsocket.h"
#include "addresslist.h"
#include "querydnsbase.h"
#include "utils.h"

int INTERNAL_INTERFACE_PRIMARY;
int INTERNAL_INTERFACE_SECONDARY;

sa_family_t	MainFamily = AF_UNSPEC;

static InternalInterface	Interfaces[7];

void InternalInterface_Init(int PrimaryProtocal)
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

SOCKET InternalInterface_TryBindLocal(int Port, Address_Type *Address)
{
	Address_Type Address1;
	SOCKET ret;
	const char	*LocalAddress;

	if( MainFamily == AF_INET )
	{
		LocalAddress = "127.0.0.1";
	} else {
		LocalAddress = "::1";
	}

	do {
		AddressList_ConvertToAddressFromString(&Address1, LocalAddress, Port);
		ret = InternalInterface_OpenASocket(MainFamily, &(Address1.Addr));

		++Port;
	} while( ret == INVALID_SOCKET );

	if( Address != NULL )
	{
		memcpy(Address, &Address1, sizeof(Address_Type));
	}

	return ret;
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
		return AF_UNSPEC;
	}

	if( Out != NULL )
	{
		*Out = &(Interfaces[Type].Address.Addr);
	}

	return Interfaces[Type].Address.family;
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
	Header -> _Pad = 0;
}

static int QueryContextCompare(QueryContextEntry *_1, QueryContextEntry *_2)
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
	return Bst_Init(Context, NULL, sizeof(QueryContextEntry), QueryContextCompare);
}

int InternalInterface_QueryContextAddUDP(QueryContext *Context, ControlHeader *Header)
{
	QueryContextEntry	New;

	New.Identifier = *(uint16_t *)(Header + 1);
	New.HashValue = Header -> RequestingDomainHashValue;
	New.TimeAdd = time(NULL);
	New.NeededHeader = Header -> NeededHeader;
	strcpy(New.Agent, Header -> Agent);
	memcpy(&(New.Context.BackAddress), &(Header -> BackAddress), sizeof(Address_Type));

	return Bst_Add(Context, &New);
}

int InternalInterface_QueryContextAddTCP(QueryContext *Context, ControlHeader *Header, SOCKET Socket)
{
	QueryContextEntry	New;

	New.Identifier = *(uint16_t *)(Header + 1);
	New.HashValue = Header -> RequestingDomainHashValue;
	New.TimeAdd = time(NULL);
	New.NeededHeader = Header -> NeededHeader;
	strcpy(New.Agent, Header -> Agent);
	New.Context.Socket = Socket;

	return Bst_Add(Context, &New);
}

int InternalInterface_QueryContextAddHosts(QueryContext *Context, ControlHeader *Header, uint32_t Identifier, int32_t HashValue)
{
	QueryContextEntry	New;

	New.Identifier = Identifier;
	New.HashValue = HashValue;
	New.TimeAdd = time(NULL);
	New.NeededHeader = Header -> NeededHeader;
	strcpy(New.Agent, Header -> Agent);

	memcpy(&(New.Context.Hosts.BackAddress), &(Header -> BackAddress), sizeof(Address_Type));
	New.Context.Hosts.Identifier = *(uint16_t *)(Header + 1);
	New.Context.Hosts.HashValue = Header -> RequestingDomainHashValue;
	New.Context.Hosts.Type = Header -> RequestingType;
	strcpy(New.Context.Hosts.Domain, Header -> RequestingDomain);

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

BOOL InternalInterface_QueryContextSwep(QueryContext *Context, time_t TimeOut)
{
	int32_t Start = -1;

	QueryContextEntry	*Entry;

	time_t	Now = time(NULL);

	Entry = Bst_Enum(Context, &Start);
	while( Entry != NULL )
	{
		if( Now - Entry -> TimeAdd > TimeOut )
		{
			Bst_Delete_ByNumber(Context, Start);
		}

		Entry = Bst_Enum(Context, &Start);
	}

	return Bst_IsEmpty(Context);
}

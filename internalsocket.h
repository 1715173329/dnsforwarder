#ifndef INTERNALSOCKET_H_INCLUDED
#define INTERNALSOCKET_H_INCLUDED

#include <time.h>
#include "bst.h"
#include "common.h"


typedef struct _InternalInterface {
	SOCKET			Socket;
	Address_Type	Address;
} InternalInterface;

typedef enum _InternalInterfaceType {
	INTERNAL_INTERFACE_UDP_INCOME = 0,
	INTERNAL_INTERFACE_TCP_INCOME = 1,
	INTERNAL_INTERFACE_HOSTS = 2,
	INTERNAL_INTERFACE_UDP_QUERY = 3,
	INTERNAL_INTERFACE_TCP_QUERY = 4

} InternalInterfaceType;

extern int INTERNAL_INTERFACE_PRIMARY;
extern int INTERNAL_INTERFACE_SECONDARY;

extern sa_family_t	MainFamily;

void InternalInterface_Init(int PrimaryProtocal);

SOCKET InternalInterface_OpenASocket(sa_family_t Family, struct sockaddr *Address);

SOCKET InternalInterface_Open(const char *AddressPort, InternalInterfaceType Type, int DefaultPort);

SOCKET InternalInterface_Open2(const char *Address, int Port, InternalInterfaceType Type);

SOCKET InternalInterface_TryBindLocal(int Port, Address_Type *Address);

SOCKET InternalInterface_TryOpenLocal(int Port, InternalInterfaceType Type);

SOCKET InternalInterface_OpenTCP(const char *AddressPort, InternalInterfaceType Type, int DefaultPort);

SOCKET InternalInterface_GetSocket(InternalInterfaceType Type);

sa_family_t InternalInterface_GetAddress(InternalInterfaceType Type, struct sockaddr **Out);

int InternalInterface_SendTo(InternalInterfaceType Type, SOCKET ThisSocket, char *Content, int ContentLength);

typedef struct _ControlHeader {
	int32_t	_Pad;

	Address_Type	BackAddress;

	char	RequestingDomain[256];
	int		RequestingDomainHashValue;
	int		RequestingType;

	BOOL	NeededHeader;

	char	Agent[LENGTH_OF_IPV6_ADDRESS_ASCII + 1];
} ControlHeader;

void InternalInterface_InitControlHeader(ControlHeader *Header);

typedef struct _QueryContextEntry {
	uint32_t	Identifier;
	int32_t		HashValue;
	time_t		TimeAdd;
	BOOL		NeededHeader;
	char		Agent[LENGTH_OF_IPV6_ADDRESS_ASCII + 1];
	union	{
		Address_Type	BackAddress;
		SOCKET	Socket;
		struct {
			Address_Type	BackAddress;
			uint32_t		Identifier;
			int32_t			HashValue;
			int				Type;
            char			Domain[129];
		} Hosts;
	} Context;
} QueryContextEntry;

typedef Bst	QueryContext;

int InternalInterface_InitQueryContext(QueryContext *Context);

int InternalInterface_QueryContextAddUDP(QueryContext *Context, ControlHeader *Header);

int InternalInterface_QueryContextAddTCP(QueryContext *Context, ControlHeader *Header, SOCKET Socket);

int InternalInterface_QueryContextAddHosts(QueryContext *Context, ControlHeader *Header, uint32_t Identifier, int32_t HashValue);

int32_t InternalInterface_QueryContextFind(QueryContext *Context, uint32_t Identifier, int32_t HashValue);

#define	InternalInterface_QueryContextRemoveByNumber(context_ptr, number)	(Bst_Delete_ByNumber((context_ptr), (number)))

void InternalInterface_QueryContextRemove(QueryContext *Context, uint32_t Identifier, int32_t HashValue);

BOOL InternalInterface_QueryContextSwep(QueryContext *Context, time_t TimeOut);


#endif // INTERNALSOCKET_H_INCLUDED

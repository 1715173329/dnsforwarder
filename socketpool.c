#include "socketpool.h"
#include "utils.h"

static int Compare(const SocketUnit *_1, const SocketUnit *_2)
{
	return ( _1 -> Address - _2 -> Address );
}

int SocketPool_Init(SocketPool *sp)
{
	return Bst_Init(sp, NULL, sizeof(SocketUnit), (int (*)(const void*, const void*))Compare);
}

SOCKET *SocketPool_Add(SocketPool *sp, struct sockaddr *Address)
{
	SocketUnit su;

	su.Address = Address;
	su.Sock = SafeMalloc(sizeof(SOCKET));
	*(su.Sock) = INVALID_SOCKET;

	if( Bst_Add(sp, &su) != 0 )
	{
		SafeFree(su.Sock);
		return NULL;
	}

	return su.Sock;
}

SOCKET *SocketPool_Fetch(SocketPool *sp, struct sockaddr *Address)
{
	int32_t Result;
	SocketUnit su = {Address, NULL};

	if( Address == NULL )
	{
		return NULL;
	}

	Result = Bst_Search(sp, &su, NULL);
	if( Result < 0 )
	{
        return SocketPool_Add(sp, Address);
	} else {
		SocketUnit *sup;

		sup = Bst_GetDataByNumber(sp, Result);
		return sup -> Sock;
	}
}

SOCKET *SocketPool_IsSet(SocketPool *sp, fd_set *fs)
{
	SocketUnit	*sup;
	int32_t		Start = -1;

	sup = Bst_Enum(sp, &Start);
	while( sup != NULL )
	{
		if( FD_ISSET(*(sup -> Sock), fs) )
		{
			return sup -> Sock;
		}
	}

	return NULL;
}

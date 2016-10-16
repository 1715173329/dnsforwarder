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

SOCKET *SocketPool_Add(SocketPool *sp, struct sockaddr *Address, time_t **LastPtr)
{
	SocketUnit su;

	su.Address = Address;
	su.Sock = SafeMalloc(sizeof(SOCKET));
	if( su.Sock == NULL )
	{
		return NULL;
	}
	*(su.Sock) = INVALID_SOCKET;
	su.Last = SafeMalloc(sizeof(time_t));
	if( su.Last == NULL )
	{
		return NULL;
	}

	if( Bst_Add(sp, &su) != 0 )
	{
		SafeFree(su.Sock);
		return NULL;
	}

	*LastPtr = su.Last;
	return su.Sock;
}

SOCKET *SocketPool_Fetch(SocketPool *sp, struct sockaddr *Address, time_t **LastPtr)
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
        return SocketPool_Add(sp, Address, LastPtr);
	} else {
		SocketUnit *sup;

		sup = Bst_GetDataByNumber(sp, Result);
		*LastPtr = sup -> Last;
		return sup -> Sock;
	}
}

SOCKET *SocketPool_IsSet(SocketPool *sp, fd_set *fs, time_t **LastPtr)
{
	SocketUnit	*sup;
	int32_t		Start = -1;

	sup = Bst_Enum(sp, &Start);
	while( sup != NULL )
	{
		if( FD_ISSET(*(sup -> Sock), fs) )
		{
			*LastPtr = sup -> Last;
			return sup -> Sock;
		}
	}

	return NULL;
}

void SocketPool_CloseAll(SocketPool *sp)
{
	SOCKET	*sock;
	int32_t	Start = -1;

	sock = Bst_Enum((Bst *)sp, &Start);
	while( sock != NULL )
	{
		if( *sock != INVALID_SOCKET )
		{
			CLOSE_SOCKET(*sock);
			*sock = INVALID_SOCKET;
		}

		sock = Bst_Enum((Bst *)sp, &Start);
	}
}

#ifndef SOCKETPOOL_H_INCLUDED
#define SOCKETPOOL_H_INCLUDED

#include "bst.h"
#include "common.h"

typedef struct _SocketUnit {
	struct sockaddr	*Address;
	SOCKET          *Sock;
} SocketUnit;

typedef Bst SocketPool;

int SocketPool_Init(SocketPool *sp);

SOCKET *SocketPool_Add(SocketPool *sp, struct sockaddr *Address);

SOCKET *SocketPool_Fetch(SocketPool *sp, struct sockaddr *Address);

SOCKET *SocketPool_IsSet(SocketPool *sp, fd_set *fs);
#endif // SOCKETPOOL_H_INCLUDED

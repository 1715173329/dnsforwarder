#ifndef SOCKETPOOL_H_INCLUDED
#define SOCKETPOOL_H_INCLUDED

#include <time.h>
#include "bst.h"
#include "common.h"

typedef struct _SocketUnit {
	struct sockaddr	*Address;
	SOCKET          *Sock;
	time_t			*Last;
} SocketUnit;

typedef Bst SocketPool;

int SocketPool_Init(SocketPool *sp);

SOCKET *SocketPool_Add(SocketPool *sp, struct sockaddr *Address, time_t **LastPtr);

SOCKET *SocketPool_Fetch(SocketPool *sp, struct sockaddr *Address, time_t **LastPtr);

SOCKET *SocketPool_IsSet(SocketPool *sp, fd_set *fs, time_t **LastPtr);

void SocketPool_CloseAll(SocketPool *sp);
#endif // SOCKETPOOL_H_INCLUDED

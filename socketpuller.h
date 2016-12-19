#ifndef SOCKETPULLER_H_INCLUDED
#define SOCKETPULLER_H_INCLUDED
/** Non-thread-safe socket puller for reading */

#include "socketpool.h"
#include "common.h"
#include "oo.h"

typedef struct _SocketPuller SocketPuller;

struct _SocketPuller{
    PRIMEMB SocketPool  p;
    PRIMEMB fd_set  s;
    PRIMEMB SOCKET  Max;

    PUBMEMB int (*Add)(SocketPuller *p,
                       SOCKET s,
                       const void *Data,
                       int DataLength
                       );

    PUBMEMB SOCKET (*Select)(SocketPuller *p,
                             struct timeval *tv,
                             const void **Data
                             );

    PUBMEMB void (*Free)(SocketPuller *p);
};

int SocketPuller_Init(SocketPuller *p);

#endif // SOCKETPULLER_H_INCLUDED

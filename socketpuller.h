#ifndef SOCKETPULLER_H_INCLUDED
#define SOCKETPULLER_H_INCLUDED
/** Non-thread-safe socket puller for reading */

#include "socketpool.h"
#include "common.h"
#include "oo.h"

typedef struct _SocketPuller SocketPuller;

struct _SocketPuller{
    PRIMENB SocketPool  p;
    PRIMENB fd_set  s;
    PRIMENB SOCKET  Max;

    PUBMENB int (*Add)(SocketPuller *p,
                       SOCKET s,
                       const char *Data,
                       int DataLength
                       );

    PUBMENB SOCKET (*Select)(SocketPuller *p,
                             struct timeval *tv,
                             const char **Data
                             );

    PUBMENB void (*Free)(SocketPuller *p);
};

#endif // SOCKETPULLER_H_INCLUDED

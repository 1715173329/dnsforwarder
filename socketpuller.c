#include "socketpuller.h"

PUBFUNC int SocketPuller_Add(SocketPuller *p,
                             SOCKET s,
                             const char *Data,
                             int DataLength
                             )
{
    if( s == INVALID_SOCKET )
    {
        return -11;
    }

    if( p->p.Add(&(p->p), s, Data, DataLength) != 0 )
    {
        return -16;
    }

    if( s > p->Max )
    {
        p->Max = s;
    }

    FD_SET(s, &(p->s));

    return 0;
}

PUBFUNC SOCKET SocketPuller_Select(SocketPuller *p,
                                   struct timeval *tv,
                                   const char **Data
                                   )
{
    fd_set ReadySet;

    ReadySet = p->s;

    switch( select(p->Max, &ReadySet, NULL, NULL, tv) )
    {
    case SOCKET_ERROR:
        /** TODO: Show fatal error */
        /* No break; */
    case 0:
        return INVALID_SOCKET;
        break;

    default:
        return p->p.FetchOnSet(&(p->p), &ReadySet, Data);
        break;
    }
}

PUBFUNC void SocketPuller_Free(SocketPuller *p)
{
    p->p.Free(&(p->p), TRUE);
}

int SocketPuller_Init(SocketPuller *p)
{
    p->Add = SocketPuller_Add;
    p->Select = SocketPuller_Select;
    p->Free = SocketPuller_Free;

    FD_ZERO(&(p->s));
    return SocketPool_Init(&(p->p));
}

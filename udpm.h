#ifndef UDPM_H_INCLUDED
#define UDPM_H_INCLUDED

#include "iheader.h"
#include "bst.h"
#include "common.h"
#include "addresslist.h"
#include "readconfig.h"

typedef struct _UdpmContextItem{
    IHeader     h;
    uint32_t	i; /* Query identifier */
    time_t		t; /* Time added */
} UdpmContextItem;

typedef struct _UdpmContext UdpmContext;

struct _UdpmContext{
    /* private */
    Bst	d;

    /* public */
    int (*Add)(UdpmContext *c, IHeader *h /* Entity followed */);
    int (*FindAndRemove)(UdpmContext *c,
                         IHeader *h, /* Entity followed */
                         UdpmContextItem *i
                         );
};

typedef struct _UdpM UdpM;

struct _UdpM {
    /* private */
    volatile SOCKET  Departure;
    SOCKET  SendBack;
    UdpmContext Context;

    EFFECTIVE_LOCK  Lock;

    ThreadHandle    WorkThread;

    AddressList     AddrList;
    struct { /* parallel query informations */
        /* When these two are not NULL, parallel-query is enabled */
        struct sockaddr **addrs; /* Free it when no longer needed */
        sa_family_t familiy;
        int addrlen;
    } Parallels;

    /* public */
    int (*Send)(UdpM *m, IHeader *h, /* Entity followed */ int FullLength);
};

#endif // UDPM_H_INCLUDED

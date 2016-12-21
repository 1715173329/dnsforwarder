#include <string.h>
#include "socketpool.h"
#include "utils.h"

static int SocketPool_Add(SocketPool *sp,
                          SOCKET Sock,
                          const void *Data,
                          int DataLength
                          )
{
	SocketUnit su;

	su.Sock = Sock;

    if( Data != NULL )
    {
        su.Data = sp->d.Add(&(sp->d), Data, DataLength, TRUE);

    } else {
        su.Data = NULL;
    }

	if( sp->t.Add(&(sp->t), &su) != NULL )
	{
		return -27;
	}

	return 0;
}

typedef struct _SocketPool_Fetch_Arg
{
    SOCKET Sock;
    fd_set *fs;
} SocketPool_Fetch_Arg;

static int SocketPool_Fetch_Inner(Bst *t,
                                  const SocketUnit *Data,
                                  SocketPool_Fetch_Arg *Arg)
{
    if( FD_ISSET(Data->Sock, Arg->fs) )
    {
        Arg->Sock = Data->Sock;
        return 1;
    }

    return 0;
}

static SOCKET SocketPool_FetchOnSet(SocketPool *sp,
                                    fd_set *fs,
                                    const void **Data
                                    )
{
    SocketPool_Fetch_Arg ret = {INVALID_SOCKET, fs};

    sp->t.Enum(&(sp->t),
               (Bst_Enum_Callback)SocketPool_Fetch_Inner,
               &ret
               );

    return ret.Sock;
}

static int SocketPool_CloseAll_Inner(Bst *t,
                                     const SocketUnit *Data,
                                     void *Unused
                                     )
{
    if( Data->Sock != INVALID_SOCKET )
    {
        CLOSE_SOCKET(Data->Sock);
    }

    return 0;
}

static void SocketPool_CloseAll(SocketPool *sp)
{
    sp->t.Enum(&(sp->t),
               (Bst_Enum_Callback)SocketPool_CloseAll_Inner,
               NULL
               );
}

static void SocketPool_Free(SocketPool *sp, BOOL CloseAllSocket)
{
    if( CloseAllSocket )
    {
        SocketPool_CloseAll(sp);
    }

    sp->t.Free(&(sp->t));
    sp->d.Free(&(sp->d));
}

static int Compare(const SocketUnit *_1, const SocketUnit *_2)
{
	return (int)(_1 -> Sock) - (int)(_2 -> Sock);
}

int SocketPool_Init(SocketPool *sp)
{
    if( Bst_Init(&(sp->t),
                    sizeof(SocketUnit),
                    (CompareFunc)Compare
                    )
       != 0 )
    {
        return -113;
    }

    if( StableBuffer_Init(&(sp->d)) != 0 )
    {
        sp->t.Free(&(sp->t));
        return -119;
    }

    sp->Add = SocketPool_Add;
    sp->CloseAll = SocketPool_CloseAll;
    sp->FetchOnSet = SocketPool_FetchOnSet;
    sp->Free = SocketPool_Free;

    return 0;
}

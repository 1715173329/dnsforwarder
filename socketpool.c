#include <string.h>
#include "socketpool.h"
#include "utils.h"

static int SocketPool_Add(SocketPool *sp,
                          SOCKET Sock,
                          const char *Data,
                          int DataLength
                          )
{
	SocketUnit su;

	su.Sock = Sock;

    if( Data != NULL )
    {
        su.Data = sp->d.Add(&(sp->d), Data, DataLength);
    } else {
        su.Data = NULL;
    }

	if( Bst_Add(&(sp->t), &su) != 0 )
	{
		return -27;
	}

	return 0;
}

static SOCKET SocketPool_FetchOnSet(SocketPool *sp,
                                    fd_set *fs,
                                    const char **Data
                                    )
{
	SocketUnit	*sup;
	int32_t		Start = -1;

	sup = Bst_Enum(&(sp->t), &Start);
	while( sup != NULL )
	{
		if( FD_ISSET(sup->Sock, fs) )
		{
		    if( Data != NULL )
            {
                *Data = sup->Data;
            }
			return sup->Sock;
		}
		sup = Bst_Enum(&(sp->t), &Start);
	}

	return INVALID_SOCKET;
}

static void SocketPool_CloseAll(SocketPool *sp)
{
	SocketUnit	*sup;
	int32_t		Start = -1;

	sup = Bst_Enum(&(sp->t), &Start);
	while( sup != NULL )
	{
	    if( sup->Sock != INVALID_SOCKET )
        {
            CLOSE_SOCKET(sup->Sock);
        }

		sup = Bst_Enum(&(sp->t), &Start);
	}
}

static void SocketPool_Free(SocketPool *sp, BOOL CloseAllSocket)
{
    if( CloseAllSocket )
    {
        SocketPool_CloseAll(sp);
    }

    Bst_Free(&(sp->t));
    sp->d.Free(&(sp->d));
}

static int Compare(const SocketUnit *_1, const SocketUnit *_2)
{
	return (int)(_1 -> Sock) - (int)(_2 -> Sock);
}

int SocketPool_Init(SocketPool *sp)
{
    if( Bst_Init(&(sp->t),
                    NULL,
                    sizeof(SocketUnit),
                    (int (*)(const void*, const void*))Compare
                    )
       != 0 )
    {
        return -113;
    }

    if( StableBuffer_Init(&(sp->d)) != 0 )
    {
        Bst_Free(&(sp->t));
        return -119;
    }

    sp->Add = SocketPool_Add;
    sp->CloseAll = SocketPool_CloseAll;
    sp->FetchOnSet = SocketPool_FetchOnSet;
    sp->Free = SocketPool_Free;

    return 0;
}

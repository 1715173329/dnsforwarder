#include <string.h>
#include "udpm.h"
#include "debug.h"
#include "utils.h"

/** Context handling */
static void UdpmContext_Swep(UdpmContext *c, int TimeOut)
{
	int32_t Start = -1;
	int		Number = 1;

	UdpmContextItem *i;

	time_t	Now = time(NULL);

	i = Bst_Enum(&(c->d), &Start);
	while( i != NULL )
    {
		if( Now - i->t > TimeOut )
		{
            /** TODO: Show timeout message, domain statistic, address advanced */
			Bst_Delete_ByNumber(&(c->d), Start);

			++Number;
		}

		i = Bst_Enum(&(c->d), &Start);
    }
}

static int UdpmContext_Add(UdpmContext *c, IHeader *h /* Entity followed */)
{
    UdpmContextItem n;
    const char *e = (const char *)(h + 1);
    int ret;

    if( h == NULL )
    {
        return -21;
    }

    memcpy(&(n.h), h, sizeof(UdpmContextItem));
    n.i = *(uint16_t *)e;
    n.t = time(NULL);

    ret = Bst_Add(&(c->d), &n);

    if( ret != 0 )
    {
        return 0;
    } else {
        return -83;
    }
}

static int UdpmContext_FindAndRemove(UdpmContext *c,
                                     IHeader *h, /* Entity followed */
                                     UdpmContextItem *i
                                     )
{
    UdpmContextItem k;
    const char *e = (const char *)(h + 1);

    int r;
    const char *ri;

    k.i = *(uint16_t *)e;
    k.h.HashValue = h->HashValue;

    r = Bst_Search(&(c->d), &k, NULL);
    if( r < 0 )
    {
        return -60;
    }

    ri = Bst_GetDataByNumber(&(c->d), r);
    memcpy(i, ri, sizeof(UdpmContextItem));

    Bst_Delete_ByNumber(&(c->d), r);

    return 0;
}

static int UdpmContextCompare(const void *_1, const void *_2)
{
    const UdpmContextItem *One = (UdpmContextItem *)_1;
    const UdpmContextItem *Two = (UdpmContextItem *)_2;

	if( One->i != Two->i )
	{
		return (int)(One->i) - (int)(Two->i);
	} else {
		return (One->h.HashValue) - (int)(Two->h.HashValue);
	}
}

static int UdpmContext_Init(UdpmContext *c)
{
    if( c == NULL )
    {
        return -86;
    }

    c->Add = UdpmContext_Add;
    c->FindAndRemove = UdpmContext_FindAndRemove;

    if( Bst_Init(&(c->d),
                    NULL,
                    sizeof(UdpmContextItem),
                    UdpmContextCompare
                    )
       != 0
       )
    {
        return -106;
    }

    return 0;
}

/** Module handling */
static void UdpM_Works(void *Module)
{
    UdpM *m = (UdpM *)Module;

    struct sockaddr *addr;

    #define BUF_LENGTH  2048
    char *ReceiveBuffer;
    IHeader *Header;

    #define LEFT_LENGTH  (BUF_LENGTH - sizeof(IHeader))
    char *Entity;

    fd_set	ReadSet, ReadySet;

	static const struct timeval	LongTime = {3600, 0};
	static const struct timeval	ShortTime = {5, 0};

	struct timeval	TimeLimit = LongTime;

    ReceiveBuffer = SafeMalloc(BUF_LENGTH);
    if( ReceiveBuffer == NULL )
    {
        /** TODO: Show fatal error */
        return;
    }

    Header = (IHeader *)ReceiveBuffer;
    Entity = ReceiveBuffer + sizeof(IHeader);

    while( TRUE )
    {
        int RecvState;
        UdpmContextItem ci;
        int ContextState;

        /* Set up socket */
        EFFECTIVE_LOCK_GET(m->Lock);
        if( m->Departure == INVALID_SOCKET )
        {
            if( m->Parallels.addrs == NULL )
            {
                sa_family_t	family;

                addr = AddressList_GetOne(&(m->AddrList), &family);
                if( addr == NULL )
                {
                    /** TODO: Show fatal error */
                    EFFECTIVE_LOCK_RELEASE(m->Lock);
                    return;
                }

                m->Departure = socket(family, SOCK_DGRAM, IPPROTO_UDP);
            } else { /* Parallel query */
                m->Departure = socket(m->Parallels.familiy,
                                      SOCK_DGRAM,
                                      IPPROTO_UDP
                                      );
            }

            if( m->Departure == INVALID_SOCKET )
            {
                /** TODO: Show fatal error */
                EFFECTIVE_LOCK_RELEASE(m->Lock);
                return;
            }

            FD_ZERO(&ReadSet);
            FD_SET(m->Departure, &ReadSet);
        }
        EFFECTIVE_LOCK_RELEASE(m->Lock);

        ReadySet = ReadSet;
        switch( select(m->Departure + 1, &ReadySet, NULL, NULL, &TimeLimit) )
        {
            case SOCKET_ERROR:
                ERRORMSG("SOCKET_ERROR Reached, 201.\n");
                ERRORMSG("SOCKET_ERROR Reached, 201.\n");
                ERRORMSG("SOCKET_ERROR Reached, 201.\n");
                ERRORMSG("SOCKET_ERROR Reached, 201.\n");
                ERRORMSG("SOCKET_ERROR Reached, 201.\n");
                ERRORMSG("SOCKET_ERROR Reached, 201.\n");
                ERRORMSG("SOCKET_ERROR Reached, 201.\n");
                ERRORMSG("SOCKET_ERROR Reached, 201.\n");
                ERRORMSG("SOCKET_ERROR Reached, 201.\n");
                ERRORMSG("SOCKET_ERROR Reached, 201.\n");
                ERRORMSG("SOCKET_ERROR Reached, 201.\n");
                while( TRUE )
                {
                    SLEEP(32767);
                }
                break;

            case 0:
                UdpmContext_Swep(&(m->Context), 10);
                TimeLimit = LongTime;
                continue;
                break;

            default:
                TimeLimit = ShortTime;
                /* Goto recv job */
                break;
        }

        /* recv */
        RecvState = recvfrom(m->Departure,
                             Entity,
                             LEFT_LENGTH,
                             0,
                             NULL,
                             NULL
                             );

        /** TODO: Error handlings, address advanced */

        /* Fill IHeader */
        IHeader_Fill(Header, FALSE, Entity, RecvState, NULL, AF_UNSPEC, NULL);

        /* Fetch context item */
        EFFECTIVE_LOCK_GET(m->Lock);
        ContextState = m->Context.FindAndRemove(&(m->Context), Header, &ci);
        EFFECTIVE_LOCK_RELEASE(m->Lock);
        if( ContextState == 0 )
        {
            int SentState;
            if( ci.h.ReturnHeader )
            {
                memcpy(Header, &(ci.h), sizeof(IHeader));
                SentState = sendto(m->SendBack,
                                   ReceiveBuffer,
                                   RecvState + sizeof(IHeader),
                                   0,
                                   (const struct sockaddr *)&(Header->BackAddress.Addr),
                                   GetAddressLength(Header->BackAddress.family)
                                   );
            } else {
                SentState = sendto(m->SendBack,
                                   Entity,
                                   RecvState,
                                   0,
                                   (const struct sockaddr *)&(Header->BackAddress.Addr),
                                   GetAddressLength(Header->BackAddress.family)
                                   );
            }

            /** TODO: Error handlings, Show message, Domain statistic, add cache*/
        }
    }

    SafeFree(ReceiveBuffer);
}

static int UdpM_Send(UdpM *m,
                     IHeader *h, /* Entity followed */
                     int FullLength
                     )
{
    int ret;
    EFFECTIVE_LOCK_GET(m->Lock);

    if( m->Context.Add(&(m->Context), h) != 0 )
    {
        EFFECTIVE_LOCK_RELEASE(m->Lock);
        return -242;
    }

    if( m->Departure != INVALID_SOCKET )
    {
        if( m->Parallels.addrs != NULL )
        { /* Parallel query */
            struct sockaddr **a = m->Parallels.addrs;

            ret = 0;

            while( *a != NULL )
            {
                ret |= (sendto(m->Departure,
                              (const void *)(h + 1),
                              FullLength - sizeof(IHeader),
                              0,
                              *a,
                              m->Parallels.addrlen) > 0
                       );

                ++a;
            }

            ret = !ret;
        } else {
            struct sockaddr *a;
            sa_family_t	family;

            a = AddressList_GetOne(&(m->AddrList), &family);
            if( a == NULL )
            {
                /** TODO: Fatal error handlings */
                ret = -277;
            }

            ret = (sendto(m->Departure,
                          (const void *)(h + 1),
                          FullLength - sizeof(IHeader),
                          0,
                          a,
                          GetAddressLength(family)
                          ) > 0
                   );

            /** TODO: Error handlings */

        }
    }

    EFFECTIVE_LOCK_RELEASE(m->Lock);
    return ret;
}

int UdpM_Init(UdpM *m, SOCKET SendBack, ConfigFileInfo *ConfigInfo)
{
    BOOL Parallel;
    StringList	*Addresses;
    StringListIterator  sli;
    const char *Itr;

    if( m == NULL || SendBack == INVALID_SOCKET || ConfigInfo == NULL )
    {
        return -141;
    }

    m->Departure = INVALID_SOCKET;
    m->SendBack = SendBack;

    Addresses = ConfigGetStringList(ConfigInfo, "UDPServer");
    if( Addresses == NULL )
    {
        return -163;
    }

    if( StringListIterator_Init(&sli, Addresses) != 0 )
    {
        return -169;
    }

    if( AddressList_Init(&(m->AddrList)) != 0 )
    {
        return -171;
    }

    Itr = sli.Next(&sli);
    while( Itr != NULL )
    {
        AddressList_Add_From_String(&(m->AddrList), Itr, 53);
        Itr = sli.Next(&sli);
    }

    Parallel = ConfigGetBoolean(ConfigInfo, "ParallelQuery");
    if( Parallel )
    {
        if( AddressList_GetOneBySubscript(&(m->AddrList),
                                          &(m->Parallels.familiy),
                                          0
                                          )
           == NULL )
        {
            return -184;
        }

        m->Parallels.addrs =
            AddressList_GetPtrListOfFamily(&(m->AddrList),
                                           m->Parallels.familiy
                                           );

        m->Parallels.addrlen = GetAddressLength(m->Parallels.familiy);

    } else {
        m->Parallels.addrs = NULL;
        m->Parallels.familiy = AF_UNSPEC;
        m->Parallels.addrlen = 0;
    }

    if( UdpmContext_Init(&(m->Context)) != 0 )
    {
        return -143;
    }

    EFFECTIVE_LOCK_INIT(m->Lock);

    m->Send = UdpM_Send;

    CREATE_THREAD(UdpM_Works, m, m->WorkThread);

    return 0;
}

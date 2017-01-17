#include <string.h>
#include <time.h>
#include "udpm.h"
#include "logs.h"
#include "utils.h"

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
                while( TRUE )
                {
                    SLEEP(32767);
                }
                break;

            case 0:
                EFFECTIVE_LOCK_GET(m->Lock);
                m->Context.Swep(&(m->Context));
                EFFECTIVE_LOCK_RELEASE(m->Lock);

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
        IHeader_Fill(Header,
                     FALSE,
                     Entity,
                     RecvState,
                     NULL,
                     INVALID_SOCKET,
                     AF_UNSPEC,
                     NULL
                     );

        /* Fetch context item */
        EFFECTIVE_LOCK_GET(m->Lock);
        ContextState = m->Context.FindAndRemove(&(m->Context),
                                                Header,
                                                Header
                                                );
        EFFECTIVE_LOCK_RELEASE(m->Lock);
        if( ContextState == 0 )
        {
            int SentState;

            SentState = IHeader_SendBack(Header);

            /** TODO: Error handlings, Show message, Domain statistic, add cache*/
        }
    }

    SafeFree(ReceiveBuffer);
}

static int UdpM_Send(UdpM *m, IHeader *h /* Entity followed */)
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
                              h->EntityLength,
                              MSG_NOSIGNAL,
                              *a,
                              m->Parallels.addrlen) > 0
                       );

                ++a;
            }

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
                          h->EntityLength,
                          MSG_NOSIGNAL,
                          a,
                          GetAddressLength(family)
                          ) > 0
                   );

            /** TODO: Error handlings */

        }
    }

    EFFECTIVE_LOCK_RELEASE(m->Lock);
    return !ret;
}

int UdpM_Init(UdpM *m, const char *Services, BOOL Parallel)
{
    StringList	Addresses;
    StringListIterator  sli;
    const char *Itr;

    if( m == NULL || Services == NULL )
    {
        return -141;
    }

    m->Departure = INVALID_SOCKET;
    if( StringList_Init(&Addresses, Services, ",") != 0 )
    {
        return -364;
    }

    if( StringListIterator_Init(&sli, &Addresses) != 0 )
    {
        Addresses.Free(&Addresses);
        return -169;
    }

    if( AddressList_Init(&(m->AddrList)) != 0 )
    {
        Addresses.Free(&Addresses);
        return -171;
    }

    Itr = sli.Next(&sli);
    while( Itr != NULL )
    {
        AddressList_Add_From_String(&(m->AddrList), Itr, 53);
        Itr = sli.Next(&sli);
    }

    Addresses.Free(&Addresses);

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

    if( ModuleContext_Init(&(m->Context)) != 0 )
    {
        return -143;
    }

    EFFECTIVE_LOCK_INIT(m->Lock);

    m->Send = UdpM_Send;

    CREATE_THREAD(UdpM_Works, m, m->WorkThread);

    return 0;
}

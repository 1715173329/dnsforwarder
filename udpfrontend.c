#include "udpfrontend.h"
#include "socketpuller.h"
#include "addresslist.h"
#include "utils.h"
#include "mmgr.h"

static BOOL Ipv6_Enabled = FALSE;

static SocketPuller Frontend;

static void UdpFrontend_Work(void)
{
    /* Buffer */
    #define BUF_LENGTH  2048
    char *ReceiveBuffer;
    IHeader *Header;

    #define LEFT_LENGTH  (BUF_LENGTH - sizeof(IHeader))
    char *Entity;

    ReceiveBuffer = SafeMalloc(BUF_LENGTH);
    if( ReceiveBuffer == NULL )
    {
        /** TODO: Show fatal error */
        return;
    }

    Header = (IHeader *)ReceiveBuffer;
    Entity = ReceiveBuffer + sizeof(IHeader);

    /* Loop */
    while( TRUE )
    {
        /* Address */
        char AddressBuffer[sizeof(Address_Type)];
        struct sockaddr *IncomingAddress = (struct sockaddr *)AddressBuffer;

        SOCKET sock;
        const sa_family_t *f;

        int RecvState;

        socklen_t AddrLen;

        char Agent[sizeof(Header->Agent)];

        sock = Frontend.Select(&Frontend,
                               NULL,
                               (void **)&f,
                               TRUE,
                               FALSE
                               );
        if( sock == INVALID_SOCKET )
        {
            continue;
        }

        AddrLen = sizeof(Address_Type);

        RecvState = recvfrom(sock,
                             Entity,
                             LEFT_LENGTH,
                             0,
                             IncomingAddress,
                             &AddrLen
                             );

        if( RecvState < 0 )
        {
            /** TODO: Error handling */
            continue;
        }

        if( *f == AF_INET )
        {
            IPv4AddressToAsc(IncomingAddress, Agent);
        } else {
            IPv6AddressToAsc(IncomingAddress, Agent);
        }

        IHeader_Fill(Header,
                     FALSE,
                     Entity,
                     RecvState,
                     IncomingAddress,
                     sock,
                     *f,
                     Agent
                     );

        MMgr_Send(Header, BUF_LENGTH);
    }
}

int UdpFrontend_Init(ConfigFileInfo *ConfigInfo)
{
    StringList *UDPLocal;
    StringListIterator i;
    const char *One;

    UDPLocal = ConfigGetStringList(ConfigInfo, "UDPLocal");
    if( UDPLocal == NULL )
    {
        return -11;
    }

    if( StringListIterator_Init(&i, UDPLocal) != 0 )
    {
        return -20;
    }

    if( SocketPuller_Init(&Frontend) != 0 )
    {
        return -19;
    }

    while( (One = i.Next(&i)) != NULL )
    {
        Address_Type a;
        sa_family_t f;

        SOCKET sock;

        f = AddressList_ConvertToAddressFromString(&a, One, 53);
        if( f == AF_UNSPEC )
        {
            /** TODO: Show error */
            continue;
        }

        sock = socket(f, SOCK_DGRAM, IPPROTO_UDP);
        if( sock == INVALID_SOCKET )
        {
            continue;
        }

        if( f == AF_INET6 )
        {
            Ipv6_Enabled = TRUE;
        }

        if( bind(sock,
                 (const struct sockaddr *)&(a.Addr),
                 GetAddressLength(f)
                 )
            != 0 )
        {
            CLOSE_SOCKET(sock);
            continue;
        }

        Frontend.Add(&Frontend, sock, &f, sizeof(sa_family_t));
    }

    UDPLocal->Free(UDPLocal);

    return 0;
}

BOOL Ipv6_Aviliable(void)
{
    return Ipv6_Enabled;
}

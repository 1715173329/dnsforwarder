#include <string.h>
#include "iheader.h"
#include "dnsparser.h"
#include "common.h"

void IHeader_Reset(IHeader *h)
{
    h->_Pad = 0;
    h->Agent[0] = '\0';
    h->BackAddress.family = AF_UNSPEC;
    h->Domain[0] = '\0';
    h->EDNSEnabled = FALSE;
}

int IHeader_Fill(IHeader *h,
                 BOOL ReturnHeader, /* For tcp, this will be ignored */
                 char *DnsEntity,
                 int EntityLength,
                 struct sockaddr *BackAddress, /* NULL for tcp */
                 SOCKET SendBackSocket,
                 sa_family_t Family, /* For tcp, this will be ignored */
                 const char *Agent
                 )
{
    DnsSimpleParser p;
    DnsSimpleParserIterator i;

    h->_Pad = 0;

    if( DnsSimpleParser_Init(&p, DnsEntity, EntityLength, FALSE) != 0 )
    {
        return -31;
    }

    if( DnsSimpleParserIterator_Init(&i, &p) != 0 )
    {
        return -36;
    }

    while( i.Next(&i) != NULL )
    {
        if( i.Klass != DNS_CLASS_IN )
        {
            return -42;
        }

        switch( i.Purpose )
        {
        case DNS_RECORD_PURPOSE_QUESTION:
            if( i.GetName(&i, h->Domain, sizeof(h->Domain)) < 0 )
            {
                return -46;
            }

            StrToLower(h->Domain);
            h->HashValue = ELFHash(h->Domain, 0);
            h->Type = (DNSRecordType)DNSGetRecordType(DNSJumpHeader(DnsEntity));
            break;

        case DNS_RECORD_PURPOSE_ADDITIONAL:
            if( i.Type == DNS_TYPE_OPT )
            {
                h->EDNSEnabled = TRUE;
            }
            break;

        default:
            break;
        }
    }

    h->ReturnHeader = ReturnHeader;

    if( BackAddress != NULL )
    {
        memcpy(&(h->BackAddress.Addr), BackAddress, GetAddressLength(Family));
        h->BackAddress.family = Family;
    } else {
        h->BackAddress.family = AF_UNSPEC;
    }

    h->SendBackSocket = SendBackSocket;

    if( Agent != NULL )
    {
        strncpy(h->Agent, Agent, sizeof(h->Agent));
        h->Agent[sizeof(h->Agent) - 1] = '\0';
    } else {
        h->Agent[0] = '\0';
    }

    h->EntityLength = EntityLength;

    return 0;
}

int IHeader_SendBack(IHeader *h /* Entity followed */)
{
    if( h->BackAddress.family == AF_UNSPEC )
    {
        /* TCP */
        uint16_t TcpLength = htons(h->EntityLength);
        if( send(h->SendBackSocket,
                 (const char *)&TcpLength,
                 2,
                 MSG_MORE | MSG_NOSIGNAL
                 )
            != 2 )
        {
            /** TODO: Show error */
            return -105;
        }

        if( send(h->SendBackSocket,
                 IHEADER_TAIL(h),
                 h->EntityLength,
                 MSG_NOSIGNAL
                 )
            != h->EntityLength )
        {
            /** TODO: Show error */
            return -112;
        }
    } else {
        /* UDP */
        const char *Content;
        int Length;

        if( h->ReturnHeader )
        {
            Content = (const char *)h;
            Length = h->EntityLength + sizeof(IHeader);
        } else {
            Content = IHEADER_TAIL(h);
            Length = h->EntityLength;
        }

        if( sendto(h->SendBackSocket,
                   Content,
                   Length,
                   MSG_NOSIGNAL,
                   (const struct sockaddr *)&(h->BackAddress.Addr),
                   GetAddressLength(h->BackAddress.family)
                   )
           != Length )
        {
            /** TODO: Show error */
            return -138;
        }
    }

    return 0;
}

#include <string.h>
#include "iheader.h"
#include "dnsparser.h"
#include "utils.h"

void IHeader_Reset(IHeader *h)
{
    h->_Pad = 0;
    h->Agent[0] = '\0';
    h->BackAddress.family = AF_UNSPEC;
    h->Domain[0] = '\0';
}

int IHeader_Fill(IHeader *h,
                 BOOL ReturnHeader,
                 const char *DnsEntity,
                 int EntityLength,
                 struct sockaddr *BackAddress,
                 sa_family_t Family,
                 const char *Agent
                 )
{
    h->_Pad = 0;

    if( DNSGetHostName(DnsEntity,
                       EntityLength,
                       DNSJumpHeader(DnsEntity),
                       h->Domain,
                       sizeof(h->Domain)
                       )
       < 0 )
    {
        return -1;
    }

    StrToLower(h->Domain);
    h->HashValue = ELFHash(h->Domain, 0);

    h->Type = (DNSRecordType)DNSGetRecordType(DNSJumpHeader(DnsEntity));
    h->ReturnHeader = ReturnHeader;

    memcpy(&(h->BackAddress.Addr), BackAddress, GetAddressLength(Family));
    h->BackAddress.family = Family;

    strncpy(h->Agent, Agent, sizeof(h->Agent));
    h->Agent[sizeof(h->Agent) -1] = '\0';

    return 0;
}

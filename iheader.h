#ifndef IHEADER_H_INCLUDED
#define IHEADER_H_INCLUDED

#include "dnsrelated.h"

typedef struct _IHeader IHeader;

struct _IHeader{
	int32_t _Pad; /* Must be 0 */

	Address_Type    BackAddress;

	char	        Domain[256];
	int             HashValue;
	DNSRecordType   Type;

	BOOL            ReturnHeader;

	char            Agent[LENGTH_OF_IPV6_ADDRESS_ASCII + 1];
};

#define IHEADER_TAIL(ptr)   (void *)((IHeader *)(ptr) + 1)

void IHeader_Reset(IHeader *h);

int IHeader_Fill(IHeader *h,
                 BOOL ReturnHeader,
                 const char *DnsEntity,
                 int EntityLength,
                 struct sockaddr *BackAddress,
                 sa_family_t Family,
                 const char *Agent
                 );

#endif // IHEADER_H_INCLUDED

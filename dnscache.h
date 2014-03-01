#ifndef _DNS_CACHE_
#define _DNS_CACHE_

//#include "common.h"
#include "dnsrelated.h"
#include "extendablebuffer.h"

int DNSCache_Init(void);

BOOL Cache_IsInited(void);

int DNSCache_AddItemsToCache(char *DNSBody, time_t CurrentTime);

int DNSCache_FetchFromCache(char *RequestContent, int RequestLength, int BufferLength);

void DNSCacheClose(void);

#endif /* _DNS_CACHE_ */

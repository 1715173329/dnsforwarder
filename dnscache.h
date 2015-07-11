#ifndef _DNS_CACHE_
#define _DNS_CACHE_

#include "dnsrelated.h"
#include "extendablebuffer.h"
#include "readconfig.h"

int DNSCache_Init(ConfigFileInfo *ConfigInfo);

BOOL Cache_IsInited(void);

int DNSCache_AddItemsToCache(char *DNSBody, time_t CurrentTime, const char *Domain);

int DNSCache_FetchFromCache(char *RequestContent, int RequestLength, int BufferLength);

void DNSCacheClose(ConfigFileInfo *ConfigInfo);

#endif /* _DNS_CACHE_ */

#ifndef _DNS_CACHE_
#define _DNS_CACHE_

#include "dnsrelated.h"
#include "readconfig.h"
#include "iheader.h"

int DNSCache_Init(ConfigFileInfo *ConfigInfo);

BOOL Cache_IsInited(void);

int DNSCache_AddItemsToCache(char *DNSBody,
                             int DNSBodyLength,
                             const char *Domain
                             );

int DNSCache_FetchFromCache(IHeader *h /* Entity followed */, int BufferLength);

void DNSCacheClose(ConfigFileInfo *ConfigInfo);

#endif /* _DNS_CACHE_ */

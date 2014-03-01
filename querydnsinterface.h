#ifndef QUERYDNS_INTERFACE_INCLUDED
#define QUERYDNS_INTERFACE_INCLUDED

#include "common.h"

int QueryDNSInterfaceInit(char *ConfigFile);

int QueryDNSInterfaceStart(void);

void QueryDNSInterfaceWait(void);

#endif // QUERYDNS_INTERFACE_INCLUDED

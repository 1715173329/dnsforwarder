#ifndef HOSTS_H_INCLUDED
#define HOSTS_H_INCLUDED

#include "statichosts.h"
#include "querydnsbase.h"
#include "extendablebuffer.h"

int DynamicHosts_Init(void);

BOOL Hosts_Try(const char *Domain, int Type);

int DynamicHosts_Start(void);
#endif // HOSTS_H_INCLUDED

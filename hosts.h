#ifndef HOSTS_H_INCLUDED
#define HOSTS_H_INCLUDED

#include "statichosts.h"
#include "querydnsbase.h"
#include "extendablebuffer.h"
#include "readconfig.h"

int DynamicHosts_Init(ConfigFileInfo *ConfigInfo);

BOOL Hosts_Try(const char *Domain, int Type);

int DynamicHosts_Start(ConfigFileInfo *ConfigInfo);
#endif // HOSTS_H_INCLUDED

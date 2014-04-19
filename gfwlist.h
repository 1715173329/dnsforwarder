#ifndef GFWLIST_H_INCLUDED
#define GFWLIST_H_INCLUDED

#include "common.h"
#include "readconfig.h"

int GfwList_PeriodicWork(ConfigFileInfo *ConfigInfo);

int GfwList_Init(ConfigFileInfo *ConfigInfo, BOOL StartPeriodWork);

BOOL GfwList_Match(const char *Domain, int *HashValue);

#endif // GFWLIST_H_INCLUDED

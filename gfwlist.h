#ifndef GFWLIST_H_INCLUDED
#define GFWLIST_H_INCLUDED

#include "common.h"

int GfwList_PeriodicWork(void);

int GfwList_Init(BOOL StartPeriodWork);

BOOL GfwList_Match(const char *Domain, int *HashValue);

#endif // GFWLIST_H_INCLUDED

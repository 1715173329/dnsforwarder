#ifndef EXCLUDEDLIST_H_INCLUDED
#define EXCLUDEDLIST_H_INCLUDED

#include "querydnsbase.h"
#include "stringlist.h"
#include "stringchunk.h"
#include "readconfig.h"

int ExcludedList_Init(ConfigFileInfo *ConfigInfo, DNSQuaryProtocol PrimaryProtocol);

BOOL IsDisabledType(int Type);

BOOL MatchDomain(StringChunk *List, const char *Domain, int *HashValue);

BOOL IsDisabledDomain(const char *Domain, int *HashValue);

BOOL IsExcludedDomain(const char *Domain, int *HashValue);

int LoadGfwList(void);

#endif // EXCLUDEDLIST_H_INCLUDED

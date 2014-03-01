#ifndef EXCLUDEDLIST_H_INCLUDED
#define EXCLUDEDLIST_H_INCLUDED

#include "stringlist.h"
#include "stringchunk.h"

int ExcludedList_Init(void);

BOOL IsDisabledType(int Type);

BOOL MatchDomain(StringChunk *List, const char *Domain, int *HashValue);

BOOL IsDisabledDomain(const char *Domain, int *HashValue);

BOOL IsExcludedDomain(const char *Domain, int *HashValue);

int LoadGfwList(void);

#endif // EXCLUDEDLIST_H_INCLUDED

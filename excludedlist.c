#include <string.h>
#include <time.h>
#include "excludedlist.h"
#include "querydnsbase.h"
#include "utils.h"
#include "stringchunk.h"
#include "stringlist.h"
#include "bst.h"
#include "common.h"

static Bst			DisabledTypes;

static StringChunk	DisabledDomains;

static StringChunk	ExcludedDomains;

BOOL IsDisabledType(int Type)
{
	if( Bst_Search(&DisabledTypes, &Type, NULL) >= 0 )
	{
		return TRUE;
	} else {
		return FALSE;
	}
}

BOOL MatchDomain(StringChunk *List, const char *Domain, int *HashValue)
{
	if( List == NULL )
	{
		return FALSE;
	}

	if( StringChunk_Match(List, Domain, HashValue, NULL) == TRUE )
	{
		return TRUE;
	}

	Domain = strchr(Domain + 1, '.');

	while( Domain != NULL )
	{
		if( StringChunk_Match_NoWildCard(List, Domain, NULL, NULL) == TRUE ||
			StringChunk_Match_NoWildCard(List, Domain + 1, NULL, NULL) == TRUE
			)
		{
			return TRUE;
		}

		Domain = strchr(Domain + 1, '.');
	}

	return FALSE;
}

BOOL IsDisabledDomain(const char *Domain, int *HashValue){
	return MatchDomain(&DisabledDomains, Domain, HashValue);
}

BOOL IsExcludedDomain(const char *Domain, int *HashValue)
{
	return MatchDomain(&ExcludedDomains, Domain, HashValue);
}

static int TypeCompare(const int *_1, const int *_2)
{
	return *_1 - *_2;
}

static int LoadDisableType(void)
{
	const StringList *DisableType_Str = ConfigGetStringList(&ConfigInfo, "DisabledType");

	const char *OneTypePendingToAdd_Str;
	int OneTypePendingToAdd;

	if( Bst_Init(&DisabledTypes, NULL, sizeof(int), TypeCompare) != 0 )
	{
		return -1;
	}

	if( DisableType_Str == NULL )
	{
		return 0;
	}

	OneTypePendingToAdd_Str = StringList_GetNext(DisableType_Str, NULL);
	while( OneTypePendingToAdd_Str != NULL )
	{
		sscanf(OneTypePendingToAdd_Str, "%d", &OneTypePendingToAdd);
		Bst_Add(&DisabledTypes, &OneTypePendingToAdd);

		OneTypePendingToAdd_Str = StringList_GetNext(DisableType_Str, OneTypePendingToAdd_Str);
	}

	return 0;
}

static int LoadDomains(StringChunk *List, const StringList *Domains)
{
	const char *Str;

	if( StringChunk_Init(List, NULL) < 0 )
	{
		return -1;
	}

	if( Domains == NULL )
	{
		return 0;
	}

	Str = StringList_GetNext(Domains, NULL);
	while( Str != NULL )
	{
		if( *Str == '.' )
		{
			Str++;
		}

		if( StringChunk_Add(List, Str, NULL, 0) != 0 )
		{
			return -2;
		}
		Str = StringList_GetNext(Domains, Str);
	}

	return 0;
}

int ExcludedList_Init(void)
{
	StringList *DisabledDomain = ConfigGetStringList(&ConfigInfo, "DisabledDomain");
	StringList *ExcludedDomain = ConfigGetStringList(&ConfigInfo, "ExcludedDomain");

	LoadDomains(&DisabledDomains, ConfigGetStringList(&ConfigInfo, "DisabledDomain"));

	StringList_Free(DisabledDomain);

	LoadDomains(&ExcludedDomains, ConfigGetStringList(&ConfigInfo, "ExcludedDomain"));

	StringList_Free(ExcludedDomain);

	LoadDisableType();

	INFO("Excluded & Disabled list initialized.\n");
	return 0;
}

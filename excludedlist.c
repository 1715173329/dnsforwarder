#include <string.h>
#include <time.h>
#include "excludedlist.h"
#include "querydnsbase.h"
#include "utils.h"
#include "stringchunk.h"
#include "stringlist.h"
#include "bst.h"
#include "readline.h"
#include "common.h"

static Bst			DisabledTypes;

static StringChunk	*StaticDisabled = NULL;
static StringChunk	*DynamicDisabled = NULL;
static StringChunk	*StaticExcluded = NULL;
static StringChunk	*DynamicExcluded = NULL;

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
	return MatchDomain(StaticDisabled, Domain, HashValue) || MatchDomain(DynamicDisabled, Domain, HashValue);
}

BOOL IsExcludedDomain(const char *Domain, int *HashValue)
{
	return MatchDomain(StaticExcluded, Domain, HashValue) || MatchDomain(DynamicExcluded, Domain, HashValue);
}

static int TypeCompare(const int *_1, const int *_2)
{
	return *_1 - *_2;
}

static int LoadDisableType(ConfigFileInfo *ConfigInfo)
{
	const StringList *DisableType_Str = ConfigGetStringList(ConfigInfo, "DisabledType");

	const char *OneTypePendingToAdd_Str;
	int OneTypePendingToAdd;

	if( Bst_Init(&DisabledTypes, NULL, sizeof(int), (int (*)(const void *, const void *))TypeCompare) != 0 )
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

static int LoadDomainsFromList(StringChunk *List, const StringList *Domains)
{
	const char *Str;

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

static int LoadDomainsFromFile(StringChunk *List, const char *File)
{
	FILE *fp;
	char	Domain[512];
	ReadLineStatus	Status;

	fp = fopen(File, "r");
	if( fp == NULL )
	{
		return -1;
	}

	Status = ReadLine(fp, Domain, sizeof(Domain));
	while( Status != READ_FAILED_OR_END )
	{
		if( Status == READ_DONE )
		{
			StringChunk_Add(List, Domain, NULL, 0);
		} else {
			ReadLine_GoToNextLine(fp);
		}

		Status = ReadLine(fp, Domain, sizeof(Domain));
	}

	return 0;
}

static int InitContainer(StringChunk **List)
{
	*List = malloc(sizeof(StringChunk));
	if( *List == NULL )
	{
		return -1;
	}

	if( StringChunk_Init(*List, NULL) < 0 )
	{
		return -1;
	}

	return 0;
}

int ExcludedList_Init(ConfigFileInfo *ConfigInfo)
{
	StringList *DisabledDomain;
	StringList *ExcludedDomain;
	const char *DisabledFile;
	const char *ExcludedFile;

	DisabledDomain = ConfigGetStringList(ConfigInfo, "DisabledDomain");
	if( DisabledDomain != NULL && InitContainer(&StaticDisabled) == 0 )
	{
		LoadDomainsFromList(StaticDisabled, DisabledDomain);
		StringList_Free(DisabledDomain);
	}

	ExcludedDomain = ConfigGetStringList(ConfigInfo, "ExcludedDomain");
	if( ExcludedDomain != NULL && InitContainer(&StaticExcluded) == 0 )
	{
		LoadDomainsFromList(StaticExcluded, ExcludedDomain);
		StringList_Free(ExcludedDomain);
	}

	DisabledFile = ConfigGetRawString(ConfigInfo, "DisabledList");
	if( DisabledFile != NULL && InitContainer(&DynamicDisabled) == 0 )
	{
		LoadDomainsFromFile(DynamicDisabled, DisabledFile);
	}

	ExcludedFile = ConfigGetRawString(ConfigInfo, "ExcludedList");
	if( ExcludedFile != NULL && InitContainer(&DynamicExcluded) == 0 )
	{
		LoadDomainsFromFile(DynamicExcluded, ExcludedFile);
	}

	LoadDisableType(ConfigInfo);

	INFO("Excluded & Disabled list initialized.\n");
	return 0;
}

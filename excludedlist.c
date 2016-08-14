#include <string.h>
#include <time.h>
#include "excludedlist.h"
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
	return StringChunk_Domain_Match(List, Domain, HashValue, NULL);
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
	StringList *DisableType_Str = ConfigGetStringList(ConfigInfo, "DisabledType");

	const char *OneTypePendingToAdd_Str;
	int OneTypePendingToAdd;

    StringListIterator  sli;

	if( Bst_Init(&DisabledTypes, NULL, sizeof(int), (int (*)(const void *, const void *))TypeCompare) != 0 )
	{
		return -1;
	}

	if( DisableType_Str == NULL )
	{
		return 0;
	}

	if( StringListIterator_Init(&sli, DisableType_Str) != 0 )
    {
        return -2;
    }

	OneTypePendingToAdd_Str = sli.Next(&sli);
	while( OneTypePendingToAdd_Str != NULL )
	{
		sscanf(OneTypePendingToAdd_Str, "%d", &OneTypePendingToAdd);
		Bst_Add(&DisabledTypes, &OneTypePendingToAdd);

		OneTypePendingToAdd_Str = sli.Next(&sli);
	}

	return 0;
}

static int LoadDomainsFromList(StringChunk *List, StringList *Domains)
{
	const char *Str;

	StringListIterator  sli;

	if( List == NULL || Domains == NULL )
	{
		return 0;
	}

	if( StringListIterator_Init(&sli, Domains) != 0 )
    {
        return -1;
    }

	Str = sli.Next(&sli);
	while( Str != NULL )
	{
		if( StringChunk_Add_Domain(List, Str, NULL, 0) != 0 )
		{
			return -2;
		}
		Str = sli.Next(&sli);
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
			StringChunk_Add_Domain(List, Domain, NULL, 0);
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

int ExcludedList_Init(ConfigFileInfo *ConfigInfo, DNSQuaryProtocol PrimaryProtocol)
{
	StringList *DisabledDomain = NULL;
	StringList *ExcludedDomain = NULL;
	StringList *AlwaysUDP = NULL;
	StringList *AlwaysTCP = NULL;
	const char *DisabledFile = NULL;
	const char *ExcludedFile = NULL;

	DisabledDomain = ConfigGetStringList(ConfigInfo, "DisabledDomain");
	if( DisabledDomain != NULL && InitContainer(&StaticDisabled) == 0 )
	{
		LoadDomainsFromList(StaticDisabled, DisabledDomain);
		DisabledDomain->Free(DisabledDomain);
	}

	ExcludedDomain = ConfigGetStringList(ConfigInfo, "ExcludedDomain");
	AlwaysUDP = ConfigGetStringList(ConfigInfo, "AlwaysUDP");
	AlwaysTCP = ConfigGetStringList(ConfigInfo, "AlwaysTCP");
	if( (ExcludedDomain != NULL || AlwaysUDP != NULL || AlwaysTCP != NULL)
		&& InitContainer(&StaticExcluded) == 0 )
	{
		LoadDomainsFromList(StaticExcluded, ExcludedDomain);

		if( PrimaryProtocol == DNS_QUARY_PROTOCOL_TCP )
		{
			LoadDomainsFromList(StaticExcluded, AlwaysUDP);
		} else {
			LoadDomainsFromList(StaticExcluded, AlwaysTCP);
		}

		if( ExcludedDomain != NULL )
        {
            ExcludedDomain->Free(ExcludedDomain);
        }

		if( AlwaysUDP != NULL )
        {
            AlwaysUDP->Free(AlwaysUDP);
        }

		if( AlwaysTCP != NULL )
        {
            AlwaysTCP->Free(AlwaysTCP);
        }
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

#include <string.h>
#include "stringchunk.h"
#include "utils.h"

typedef struct _EntryForString{
	int32_t	OffsetOfString;
	int32_t	OffsetOfData;
} EntryForString;

int StringChunk_Init(StringChunk *dl, StringList *List)
{
	if( dl == NULL )
	{
		return 0;
	}

	if( SimpleHT_Init(&(dl -> List_Pos), sizeof(EntryForString), 5, ELFHash) != 0 )
	{
		return -1;
	}

	if( Array_Init(&(dl -> List_W_Pos), sizeof(EntryForString), 0, FALSE, NULL) != 0 )
	{
		SimpleHT_Free(&(dl -> List_Pos));
		return -2;
	}

	if( ExtendableBuffer_Init(&(dl -> AdditionalDataChunk), 0, -1) != 0 )
	{
		SimpleHT_Free(&(dl -> List_Pos));
		Array_Free(&(dl -> List_W_Pos));
		return -3;
	}

	if( List == NULL )
	{
		dl -> List = SafeMalloc(sizeof(StringList));
		if( dl -> List == NULL )
		{
			return -4;
		}

		if( StringList_Init(dl -> List, NULL, ',') != 0 )
		{
			return -5;
		}
	} else {
		dl -> List = List;
	}

	return 0;
}

int StringChunk_Add(StringChunk	*dl,
					const char	*Str,
					const char	*AdditionalData,
					int			LengthOfAdditionalData /* The length will not be stored. */
					)
{
	EntryForString NewEntry;

	if( AdditionalData != NULL && LengthOfAdditionalData > 0 )
	{
		int32_t OffsetOfStoredTo;

		char *DataStoredTo =
						ExtendableBuffer_Expand(&(dl -> AdditionalDataChunk),
						LengthOfAdditionalData,
						&OffsetOfStoredTo
						);

		if( DataStoredTo == NULL )
		{
			return -1;
		}

		NewEntry.OffsetOfData = OffsetOfStoredTo;

		memcpy(DataStoredTo, AdditionalData, LengthOfAdditionalData);

	} else {
		NewEntry.OffsetOfData = -1;
	}

	NewEntry.OffsetOfString = StringList_Add(dl -> List, Str, ',');
	if( NewEntry.OffsetOfString < 0 )
	{
		return -1;
	}

	if( ContainWildCard(Str) )
	{
		Array_PushBack(&(dl -> List_W_Pos), &NewEntry, NULL);
	} else {
		SimpleHT_Add(&(dl -> List_Pos), Str, 0, (const char *)&NewEntry, NULL);
	}

	return 0;
}

int StringChunk_Add_Domain(StringChunk	*dl,
							const char	*Domain,
							const char	*AdditionalData,
							int			LengthOfAdditionalData /* The length will not be stored. */
							)
{
	if( *Domain == '.' )
	{
		++Domain;
	}

	return StringChunk_Add(dl, Domain, AdditionalData, LengthOfAdditionalData);
}

BOOL StringChunk_Match_NoWildCard(StringChunk	*dl,
								  const char	*Str,
								  int			*HashValue,
								  char			**Data
								  )
{
	EntryForString *FoundEntry;

	const char *FoundString;

	if( dl == NULL )
	{
		return FALSE;
	}

	FoundEntry = (EntryForString *)SimpleHT_Find(&(dl -> List_Pos), Str, 0, HashValue, NULL);
	while( FoundEntry != NULL )
	{
		FoundString = StringList_GetByOffset(dl -> List,
											 FoundEntry -> OffsetOfString
											 );
		if( strcmp(FoundString, Str) == 0 )
		{
			if( FoundEntry -> OffsetOfData >=0 && Data != NULL )
			{
				*Data = ExtendableBuffer_GetPositionByOffset(
												&(dl -> AdditionalDataChunk),
												FoundEntry -> OffsetOfData
												);
			}

			return TRUE;
		}

		FoundEntry = (EntryForString *)SimpleHT_Find(&(dl -> List_Pos), Str, 0, HashValue, (const char *)FoundEntry);
	}

	return FALSE;

}

BOOL StringChunk_Match_OnlyWildCard(StringChunk	*dl,
									const char	*Str,
									char		**Data
									)
{
	EntryForString *FoundEntry;

	const char *FoundString;

	int loop;

	if( dl == NULL )
	{
		return FALSE;
	}

	for( loop = 0; loop != Array_GetUsed(&(dl -> List_W_Pos)); ++loop )
	{
		FoundEntry = (EntryForString *)Array_GetBySubscript(&(dl -> List_W_Pos), loop);
		if( FoundEntry != NULL )
		{
			FoundString = StringList_GetByOffset(dl -> List, FoundEntry -> OffsetOfString);
			if( WILDCARD_MATCH(FoundString, Str) == WILDCARD_MATCHED )
			{
				if( FoundEntry -> OffsetOfData >= 0 && Data != NULL )
				{
					*Data = ExtendableBuffer_GetPositionByOffset(
													&(dl -> AdditionalDataChunk),
													FoundEntry -> OffsetOfData
													);
				}
				return TRUE;
			}

		} else {
			return FALSE;
		}
	}

	return FALSE;
}

BOOL StringChunk_Match(StringChunk *dl, const char *Str, int *HashValue, char **Data)
{
	if( StringChunk_Match_NoWildCard(dl, Str, HashValue, Data) == TRUE ||
		StringChunk_Match_OnlyWildCard(dl, Str, Data) == TRUE
		)
	{
		return TRUE;
	} else {
		return FALSE;
	}
}

BOOL StringChunk_Domain_Match_NoWildCard(StringChunk *dl, const char *Domain, int *HashValue, char **Data)
{
	if( StringChunk_Match_NoWildCard(dl, Domain, HashValue, Data) == TRUE )
	{
		return TRUE;
	}

	Domain = strchr(Domain + 1, '.');

	while( Domain != NULL )
	{
		if( StringChunk_Match_NoWildCard(dl, Domain + 1, NULL, Data) == TRUE )
		{
			return TRUE;
		}

		Domain = strchr(Domain + 1, '.');
	}

	return FALSE;
}

BOOL StringChunk_Domain_Match(StringChunk *dl, const char *Domain, int *HashValue, char **Data)
{
	if( dl == NULL )
	{
		return FALSE;
	}

	return (StringChunk_Domain_Match_NoWildCard(dl, Domain, HashValue, Data) ||
			StringChunk_Match_OnlyWildCard(dl, Domain, Data) );
}

/* Start by 0 */
const char *StringChunk_Enum_NoWildCard(StringChunk *dl, int32_t *Start, char **Data)
{
	EntryForString *Result;

	Result = (EntryForString *)SimpleHT_Enum(&(dl -> List_Pos), Start);
	if( Result == NULL )
	{
		if( Data != NULL )
		{
			*Data = NULL;
		}

		return NULL;
	}

	if( Result -> OffsetOfData >= 0 && Data != NULL )
	{
		*Data = ExtendableBuffer_GetPositionByOffset(&(dl -> AdditionalDataChunk),
													 Result -> OffsetOfData
													 );
	}

	if( Result -> OffsetOfString >= 0 )
	{
		return StringList_GetByOffset(dl -> List, Result -> OffsetOfString);
	} else {
		return NULL;
	}
}

void StringChunk_Free(StringChunk *dl, BOOL FreeStringList)
{
	SimpleHT_Free(&(dl -> List_Pos));
	Array_Free(&(dl -> List_W_Pos));
	ExtendableBuffer_Free(&(dl -> AdditionalDataChunk));

	if( FreeStringList == TRUE )
	{
		StringList_Free(dl -> List);
		SafeFree(dl -> List);
	}
}

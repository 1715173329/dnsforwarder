#ifndef STRINGCHUNK_H_INCLUDED
#define STRINGCHUNK_H_INCLUDED

#include "simpleht.h"
#include "stringlist.h"
#include "array.h"
#include "extendablebuffer.h"

typedef struct _StringChunk{
	StringList	*List;

	/* Positions of every domain in `List', offsets */
	SimpleHT	List_Pos;

	/* Positions of every domain in `List_W', offsets */
	Array		List_W_Pos;

	/* Chunk of all additional datas */
	ExtendableBuffer	AdditionalDataChunk;

} StringChunk;

int StringChunk_Init(StringChunk *dl, StringList *List);

int StringChunk_Add(StringChunk *dl,
					const char *Str,
					const char *AdditionalData,
					int LengthOfAdditionalData
					);

/* NOTICE : Data address always return, not offset. */
BOOL StringChunk_Match_NoWildCard(StringChunk	*dl,
								  const char	*Str,
								  int			*HashValue,
								  char			**Data
								  );

BOOL StringChunk_Match_OnlyWildCard(StringChunk *dl,
									const char *Str,
									char **Data
									);

BOOL StringChunk_Match(StringChunk *dl, const char *Str, int *HashValue, char **Data);

const char *StringChunk_Enum_NoWildCard(StringChunk *dl, int32_t *Start, char **Data);

void StringChunk_Free(StringChunk *dl, BOOL FreeStringList);

#endif // STRINGCHUNK_H_INCLUDED

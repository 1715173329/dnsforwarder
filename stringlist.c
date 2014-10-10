#include <string.h>
#include "stringlist.h"
#include "utils.h"

static int Divide(char *Str, char Delimiter)
{
	int		Count = 0;
	char	*Itr = Str;

	for(Itr = strchr(Itr, Delimiter); Itr != NULL; Itr = strchr(Itr, Delimiter))
	{
		*Itr = '\0';
		++Itr;
		++Count;
	}

	return Count + 1;
}

int StringList_Init(__in StringList *s, __in const char *ori, __in char Delimiter)
{
	if( s == NULL )
		return -1;

	if( ori == NULL )
	{
		ExtendableBuffer_Init((ExtendableBuffer *)s, 0, -1);
		return 0;
	} else {
		if( ExtendableBuffer_Init((ExtendableBuffer *)s, strlen(ori) + 1, -1) != 0 )
		{
			return -1;
		}

		ExtendableBuffer_Add((ExtendableBuffer *)s, ori, strlen(ori) + 1);

		return Divide(ExtendableBuffer_GetData((ExtendableBuffer *)s), Delimiter);
	}
}

const char *StringList_GetNext(__in const StringList *s, __in const char *Current)
{
	const char *n;
	const char *End;
	const char *Data;

	if( s == NULL )
		return NULL;

	Data = ExtendableBuffer_GetData((ExtendableBuffer *)s);

	if( Current == NULL )
		return Data;

	End = Data + ExtendableBuffer_GetUsedBytes((ExtendableBuffer *)s);

	if( End == NULL || End == Data )
	{
		return NULL;
	}

	if( Current < Data || Current >= End )
		return NULL;

	n = Current + strlen(Current) + 1;

	return n >= End ? NULL : n;
}

const char *StringList_Get(__in StringList *s, __in int Subscript)
{
	int			i	=	0;
	const char	*itr;

	if( s == NULL || Subscript < 0 )
		return NULL;

	for(itr = ExtendableBuffer_GetData((ExtendableBuffer *)s); i < Subscript; ++i)
	{
		itr = StringList_GetNext(s, itr);
		if( itr == NULL )
			return NULL;
	}
	return itr;
}

int StringList_Count(StringList *s)
{
	int n = 0;
	const char *itr = NULL;

	if( s == NULL )
		return 0;

	for(itr = StringList_GetNext(s, itr); itr != NULL; itr = StringList_GetNext(s, itr))
	{
		++n;
	}
	return n;
}

int32_t StringList_Add(StringList *s, const char *str, char Delimiter)
{
	int Offset = ExtendableBuffer_Add((ExtendableBuffer *)s, str, strlen(str) + 1);

	if( Offset < 0 )
	{
		return -1;
	}

	Divide(s -> Data + Offset, Delimiter);

	return Offset;
}

const char *StringList_Find(StringList *s, const char *str)
{
	const char *itr = NULL;

	if( s == NULL )
		return 0;

	for(itr = StringList_GetNext(s, itr); itr != NULL; itr = StringList_GetNext(s, itr))
	{
		if( strcmp(itr, str) == 0 )
		{
			return itr;
		}
	}

	return NULL;
}

int32_t StringList_AppendLast(StringList *s, const char *str, char Delimiter)
{
	char *Tail;
	int Length = strlen(str);

	if( s == NULL )
		return 0;

	if( ExtendableBuffer_GuarantyLeft(s, Length) == FALSE )
	{
		return -1;
	}

	Tail = s -> Data + s -> Used - 1;

	s -> Used += Length;

	strcat(Tail, str);

	Divide(Tail, Delimiter);

	return 0;
}

void StringList_Catenate(StringList *des, StringList *src)
{
	if( des == NULL || src == NULL )
	{
		return;
	}

	ExtendableBuffer_Add(des, src -> Data, src -> Used);
}

const char **SplitURLs(StringList *s)
{
	const char **URLs;
	int NumberOfURLs = 0;
	int Count = StringList_Count(s);
	const char *Str_Itr;

	URLs = malloc(sizeof(char *) * (Count + 1));
	if( URLs == NULL )
	{
		return NULL;
	}

	Str_Itr = StringList_GetNext(s, NULL);
	while( Str_Itr != NULL )
	{
		URLs[NumberOfURLs] = Str_Itr;
		++NumberOfURLs;

		Str_Itr = StringList_GetNext(s, Str_Itr);
	}

	URLs[NumberOfURLs] = NULL;

	return URLs;
}

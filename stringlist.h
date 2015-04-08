#ifndef STRINGLIST_H_INCLUDED
#define STRINGLIST_H_INCLUDED

#include "common.h"
#include "extendablebuffer.h"

typedef ExtendableBuffer StringList;

int StringList_Init(__in StringList *s, __in const char *ori, __in char Delimiter);

const char *StringList_GetNext(__in const StringList *s, __in const char *Current);

const char *StringList_Get(__in StringList *s, __in int Subscript);

int StringList_Count(StringList *s);

int32_t StringList_Add(StringList *s, const char *str, char Delimiter);

int32_t StringList_AppendLast(StringList *s, const char *str, char Delimiter);

void StringList_Catenate(StringList *des, StringList *src);

#define	StringList_GetByOffset(s_ptr, offset)	((const char *)((s_ptr) -> Data + (offset)))

#define StringList_Clear(s_ptr)	(ExtendableBuffer_Reset(s_ptr))

const char *StringList_Find(StringList *s, const char *str);

#define StringList_Free(s_ptr)	(ExtendableBuffer_Free((ExtendableBuffer *)(s_ptr)))

const char **StringList_ToCharPtrArray(StringList *s);

#endif // STRINGLIST_H_INCLUDED
